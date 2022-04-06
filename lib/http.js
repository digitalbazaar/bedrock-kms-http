/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brZCapStorage from '@bedrock/zcap-storage';
import * as helpers from './helpers.js';
import * as middleware from './middleware.js';
import {asyncHandler} from '@bedrock/express';
import cors from 'cors';
import {createRequire} from 'module';
import {createValidateMiddleware as validate} from '@bedrock/validation';
import {
  defaultModuleManager as moduleManager,
  keystores
} from '@bedrock/kms';
import {meters} from '@bedrock/meter-usage-reporter';
import {
  postKeystoreBody,
  updateKeystoreConfigBody,
  postRevocationBody
} from '../schemas/bedrock-kms-http.js';
import {reportOperationUsage, SERVICE_TYPE} from './metering.js';
const require = createRequire(import.meta.url);
const {generateRandom} = require('@digitalbazaar/webkms-switch');

const {config, util: {BedrockError}} = bedrock;

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
          public: true,
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
      const id = helpers.getKeystoreId({req, localId: random, routes});
      const config = {id, meterId, ...req.body};
      const record = await keystores.insert({config});
      res.status(201).location(id).json(record.config);
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
    handleOperation);

  // invoke KMS operation on an existing key
  app.options(routes.key, cors());
  app.post(
    routes.key,
    cors(),
    handleOperation);

  // TODO: consider whether this should be exposed w/o authorization
  // https://github.com/digitalbazaar/bedrock-kms-http/issues/56

  // return a (public) key description
  app.get(
    routes.key,
    cors(),
    getKeystoreConfig,
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
          public: true,
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
