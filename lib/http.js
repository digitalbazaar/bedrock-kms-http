/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as brZCapStorage from '@bedrock/zcap-storage';
import * as helpers from './helpers.js';
import * as middleware from './middleware.js';
import * as zlib from 'node:zlib';
import {
  getConfigsQuery,
  postKeystoreBody,
  postRevocationBody,
  updateKeystoreConfigBody
} from '../schemas/bedrock-kms-http.js';
import {
  keystores,
  defaultModuleManager as moduleManager
} from '@bedrock/kms';
import {reportOperationUsage, SERVICE_TYPE} from './metering.js';
import {asyncHandler} from '@bedrock/express';
import {createProxyMiddleware} from 'http-proxy-middleware';
import {generateRandom} from '@digitalbazaar/webkms-switch';
import {meters} from '@bedrock/meter-usage-reporter';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {config, util: {BedrockError}} = bedrock;
const {cors, storage} = middleware;

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];

  // get storage cost for low-level primitives of keystores and keys as well
  // as higher-level revoked zcaps
  const storageCost = {
    ...config.kms.storageCost,
    ...cfg.storageCost
  };

  // WebKMS paths are fixed off of the base path per the spec
  const routes = {...cfg.routes};
  routes.keystores = `${routes.basePath}/keystores`;
  routes.keystore = `${routes.keystores}/:keystoreId`;
  routes.keys = `${routes.keystore}/keys`;
  routes.key = `${routes.keys}/:keyId`;
  routes.revocations = `${routes.keystore}/zcaps/revocations/:revocationId`;

  // create middleware for handling KMS operations
  const handleOperation = middleware.createKmsOperationMiddleware();

  // create middleware for getting consistent view of the keystore config
  // associated with a request
  const getKeystoreConfig = middleware.createGetKeystoreConfig({routes});

  // create KMS module proxy middleware for use with KMS operations
  const kmsModuleProxyMiddleware = _createKmsModuleProxyMiddleware();
  // create raw => json parser for routes using KMS module proxy middleware
  const rawBodyToJsonMiddleware = asyncHandler(_parseRawBodyAsJson);

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities, not cookies; CSRF is not possible. */

  // create a new keystore
  app.options(routes.keystores, cors());
  app.post(
    routes.keystores,
    cors(),
    validate({bodySchema: postKeystoreBody}),
    // meter must be checked for available usage and to obtain the meter's
    // controller prior to checking the zcap invocation (as the invocation
    // will use the meter's controller as the root controller for keystore
    // creation)
    asyncHandler(async (req, res, next) => {
      const {body: {meterId: id}} = req;
      const {meter, hasAvailable} = await meters.hasAvailable({
        id, serviceType: SERVICE_TYPE,
        resources: {storage: storageCost.keystore}
      });
      // store meter information on `req` and call next middleware
      req.meterCheck = {meter, hasAvailable};
      next();
    }),
    // now that meter information has been obtained, authorize zcap invocation
    middleware.authorizeZcapInvocation({
      async getExpectedValues() {
        const expectedHost = config.server.host;
        return {
          host: expectedHost,
          // expect root invocation target to match this route; the root zcap
          // will have its controller dynamically set to the controller of the
          // meter used as below in `getRootController`
          rootInvocationTarget: `https://${expectedHost}${routes.keystores}`
        };
      },
      async getRootController({req}) {
        // use meter's controller as the root controller for the keystore
        // creation endpoint
        return req.meterCheck.meter.controller;
      }
    }),
    asyncHandler(async (req, res) => {
      const {body: {meterId}, meterCheck: {hasAvailable}} = req;
      if(!hasAvailable) {
        // insufficient remaining storage
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 403,
          public: true
        });
      }

      // FIXME: this is a high-latency call -- consider adding the meter
      // in parallel with inserting the keystore, optimistically presuming it
      // will be added; we could decide that the case of a missing/invalid
      // meter is a possible state we have to deal in other cases anyway
      // https://github.com/digitalbazaar/bedrock-kms-http/issues/57

      // add meter
      await meters.upsert({id: meterId, serviceType: SERVICE_TYPE});

      // create a keystore for the controller
      const random = await generateRandom();
      const id = helpers.getKeystoreId({localId: random, routes});
      const config = {id, meterId, ...req.body};
      const record = await keystores.insert({config});
      res.status(201).location(id).json(record.config);
    }));

  // get all keystores by controller query
  app.get(
    routes.keystores,
    cors(),
    validate({querySchema: getConfigsQuery}),
    middleware.authorizeZcapInvocation({
      async getExpectedValues() {
        const {baseUri, host} = bedrock.config.server;
        return {
          host,
          rootInvocationTarget: `${baseUri}${routes.keystores}`
        };
      },
      async getRootController({req}) {
        return req.query.controller;
      }
    }),
    asyncHandler(async (req, res) => {
      const controller = req.query.controller;
      const options = {projection: {_id: 0, config: 1}, limit: 100};
      const results = await storage.getAll({controller, req, options});
      res.json({results});
    }));

  // update keystore config
  app.options(routes.keystore, cors());
  app.post(
    routes.keystore,
    cors(),
    validate({bodySchema: updateKeystoreConfigBody}),
    getKeystoreConfig,
    // FIXME: if a new meter is sent, set the root controller to be that of
    // the meter; otherwise set it to be that of the keystore
    middleware.authorizeKeystoreZcapInvocation(),
    asyncHandler(async (req, res) => {
      const {body: config} = req;
      const {keystore: existingConfig} = req.webkms;
      if(existingConfig.id !== config.id) {
        throw new BedrockError(
          'Configuration "id" does not match request URL.',
          'URLMismatchError', {
            httpStatusCode: 400,
            public: true,
            requestUrl: existingConfig.id,
            configId: config.id,
            expected: existingConfig.id,
            actual: config.id
          });
      }

      // add meter if a new one was given
      let {meterId} = config;
      if(meterId && meterId !== existingConfig.meterId) {
        // FIXME: only enable once root controller FIXME is addressed above
        // for the case where a new meter is sent
        throw new Error('Not implemented; meter cannot be changed.');
        // await meters.upsert({id: meterId, serviceType: SERVICE_TYPE});
      } else {
        ({meterId} = existingConfig);
      }

      // ensure `meterId` is set on config (using either existing one or new
      // one)
      config.meterId = meterId;

      // ensure `kmsModule` is set; if already set, allow `update` to proceed
      // as it will throw an error if it does not match the existing config
      if(!config.kmsModule) {
        config.kmsModule = existingConfig.kmsModule;
      }

      // the `update` API will not apply the change and will throw if
      // `config.sequence` is not valid, no need to check it here
      await keystores.update({config});

      // return new config
      res.json({config});

      // report updating config as operation usage
      reportOperationUsage({req});
    }));

  // get a keystore config
  app.get(
    routes.keystore,
    cors(),
    getKeystoreConfig,
    middleware.authorizeKeystoreZcapInvocation(),
    asyncHandler(async (req, res) => {
      res.json(req.webkms.keystore);
    }));

  // invoke a generate key KMS operation to generate a new key
  app.options(routes.keys, cors());
  app.post(
    routes.keys,
    cors(),
    getKeystoreConfig,
    kmsModuleProxyMiddleware,
    rawBodyToJsonMiddleware,
    handleOperation);

  // invoke KMS operation on an existing key
  app.options(routes.key, cors());
  app.post(
    routes.key,
    cors(),
    getKeystoreConfig,
    kmsModuleProxyMiddleware,
    rawBodyToJsonMiddleware,
    handleOperation);

  // TODO: consider whether this should be exposed w/o authorization
  // https://github.com/digitalbazaar/bedrock-kms-http/issues/56

  // return a (public) key description
  app.get(
    routes.key,
    cors(),
    getKeystoreConfig,
    kmsModuleProxyMiddleware,
    rawBodyToJsonMiddleware,
    asyncHandler(async (req, res) => {
      const {webkms: {keystore}} = req;
      const keyId = `${keystore.id}/keys/${req.params.keyId}`;
      const moduleApi = await moduleManager.get({id: keystore.kmsModule});
      const keyDescription = await moduleApi.getKeyDescription({
        keyId, controller: keystore.controller
      });
      res.json(keyDescription);
    }));

  // insert a revocation
  app.options(routes.revocations, cors());
  app.post(
    routes.revocations,
    cors(),
    validate({bodySchema: postRevocationBody}),
    getKeystoreConfig,
    middleware.authorizeZcapRevocation(),
    asyncHandler(async (req, res) => {
      const {
        body: capability,
        webkms: {keystore},
        zcapRevocation: {delegator}
      } = req;

      // check meter revocation usage; but only check to see if the meter
      // is disabled or not; allow storage overflow with revocations to
      // ensure security can be locked down; presumption is this endpoint
      // will be heavily rate limited
      const {meterId} = keystore;
      const {meter: {disabled}} = await meters.hasAvailable({
        id: meterId, serviceType: SERVICE_TYPE,
        resources: {storage: cfg.storageCost.revocation}
      });
      if(disabled) {
        // meter is disabled, do not allow storage
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 403,
          public: true
        });
      }

      // record revocation
      await brZCapStorage.revocations.insert(
        {delegator, rootTarget: keystore.id, capability});

      // success, no response body
      res.status(204).end();

      // report revocation usage as operation usage
      reportOperationUsage({req});
    }));
});

function _createKmsModuleProxyMiddleware() {
  const cfg = config['kms-http'];

  const kmsModuleProxyEntries = Object.entries(cfg.kmsModuleProxy ?? {});
  if(kmsModuleProxyEntries.length === 0) {
    // nothing to proxy; no-op
    return function kmsModuleProxyMiddleware(req, res, next) {
      next();
    };
  }

  const map = new Map();
  for(const [kmsModule, {proxyTarget}] of kmsModuleProxyEntries) {
    map.set(kmsModule, createProxyMiddleware({
      target: proxyTarget,
      // do not rewrite host header
      changeOrigin: false,
      // match TLS certificate checking expectations w/bedrock config
      secure: config['https-agent'].rejectUnauthorized,
      // include x-forward* headers
      xfwd: true,
      // do not forward websockets
      ws: false,
      on: {
        // required to rewrite body since it has been parsed
        proxyReq: _reserializeRequestBody
      }
    }));
  }
  return function kmsModuleProxyMiddleware(req, res, next) {
    const {webkms: {keystore}} = req;
    const {kmsModule} = keystore;
    const mw = map.get(kmsModule);
    if(!mw) {
      return next();
    }
    mw(req, res, next);
  };
}

// parses raw body to json
function _parseRawBodyAsJson(req, res, next) {
  try {
    // special case empty body
    req.body = req.body?.length > 0 ? JSON.parse(req.body.toString()) : {};
    next();
  } catch(cause) {
    throw new BedrockError('Failed to parse expected JSON body.', {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true},
      cause
    });
  }
}

function _reserializeRequestBody(proxyReq, req) {
  try {
    if(!(req.body?.length > 0)) {
      // nothing to send
      return;
    }

    const contentType = proxyReq.getHeader('content-type');
    if(!contentType) {
      // nothing to send
      return;
    }

    // reapply content-encoding
    const contentEncoding = String(
      proxyReq.getHeader('content-encoding')).toLowerCase();
    let data = req.body;
    if(contentEncoding === 'gzip') {
      data = zlib.gzipSync(data);
    } else if(contentEncoding === 'deflate') {
      data = zlib.deflateSync(data);
    } else if(contentEncoding === 'zstd') {
      // note: not supported by body-parser, so unreachable
      data = zlib.zstdCompressSync(data);
    } else if(contentEncoding === 'br') {
      // note: not supported by body-parser, so unreachable
      data = zlib.brotliCompressSync(data);
    } else {
      proxyReq.removeHeader('content-encoding');
    }

    const transferEncoding = proxyReq.getHeader('transfer-encoding');
    if(!transferEncoding) {
      proxyReq.setHeader('content-length', Buffer.byteLength(data));
    }
    proxyReq.write(data);
  } catch(e) {
    // pass error through `proxyReq` processing channel
    const error = e instanceof Error ? e : new Error(String(e));
    proxyReq.destroy(error);
  }
}
