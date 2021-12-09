/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const {
  authorizeZcapInvocation, authorizeZcapRevocation
} = require('@digitalbazaar/ezcap-express');
const bedrock = require('bedrock');
const BedrockKeystoreConfigStorage = require('./BedrockKeystoreConfigStorage');
const {
  defaultDocumentLoader: documentLoader,
  defaultModuleManager: moduleManager,
  keystores
} = require('bedrock-kms');
const brZCapStorage = require('bedrock-zcap-storage');
const {config, util: {BedrockError}} = bedrock;
const cors = require('cors');
const {
  createMiddleware: createOperationMiddleware,
  generateRandom
} = require('webkms-switch');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const helpers = require('./helpers');
const {meters} = require('bedrock-meter-usage-reporter');
const {validator: validate} = require('./validator');
const {
  postKeystoreBody,
  updateKeystoreConfigBody,
  postRevocationBody
} = require('../schemas/bedrock-kms-http');
const storage = new BedrockKeystoreConfigStorage();
const logger = require('./logger');

// configure usage aggregator for webkms meters
const SERVICE_TYPE = 'webkms';
meters.setAggregator({serviceType: SERVICE_TYPE, handler: _aggregateUsage});

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
  routes.revocations = `${routes.keystore}/revocations/:zcapId`;

  // create handler for reporting successful operations
  async function reportOperationUsage({req}) {
    // do not wait for usage to be reported
    const {meterId: id} = req.webkms.keystore;
    meters.use({id, operations: 1}).catch(
      error => logger.error(`Meter (${id}) usage error.`, {error}));
  }

  // create middleware for handling KMS operations
  const handleOperation = createOperationMiddleware({
    storage, moduleManager, documentLoader,
    expectedHost: config.server.host,
    inspectCapabilityChain: helpers.inspectCapabilityChain,
    onSuccess: reportOperationUsage,
    onError
  });

  // create middleware for getting consistent view of the keystore config
  // associated with a request
  const _getKeystoreConfig = createGetKeystoreConfig({routes});

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
      process.nextTick(next);
    }),
    // now that the meter information has been obtained, check zcap invocation
    _authorizeZcapInvocation({
      async getExpectedTarget({req}) {
        // use root keystore endpoint as expected target; controller will
        // be dynamically set to the meter's controller
        const expectedTarget = `https://${req.get('host')}${routes.keystores}`;
        return {expectedTarget};
      },
      async getRootController({req, rootInvocationTarget}) {
        const keystoreRoot = `https://${req.get('host')}${routes.keystores}`;
        if(rootInvocationTarget !== keystoreRoot) {
          throw new BedrockError(
            'The request URL does not match the root invocation target. ' +
            'Ensure that the capability is for the root keystores endpoint. ',
            'URLMismatchError', {
              // this error will be a `cause` in the onError handler below
              // this httpStatusCode is not operative
              httpStatusCode: 400,
              public: true,
              rootInvocationTarget,
              keystoreRoot
            });
        }
        // use meter's controller as the root controller for the keystore
        // creation endpoint
        return req.meterCheck.meter.controller;
      },
      onError
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
    _getKeystoreConfig,
    // FIXME: if a new meter is sent, set the root controller to be that of
    // the meter; otherwise set it to be that of the EDV config
    _authorizeZcapInvocation({
      getExpectedTarget: _getExpectedKeystoreTarget,
      onError
    }),
    asyncHandler(async (req, res) => {
      const {body: config} = req;
      const {keystore: existingConfig} = req.webkms;
      if(existingConfig.id !== req.body.id) {
        throw new BedrockError(
          'Configuration "id" does not match.',
          'DataError', {
            httpStatusCode: 400,
            public: true,
            expected: existingConfig.id,
            actual: config.id
          });
      }

      /* Calls to update a keystore config are expected to be infrequent, so
      calling these async functions in serial acceptable as it is the cleanest
      implementation as it prevents unnecessary meter storage / fixing that
      would have to be dealt with later if the calls were optimistically
      performed in parallel instead. */

      // add meter if a new one was given
      let {meterId} = config;
      if(meterId && meterId !== existingConfig.meterId) {
        // FIXME: only enable once root controller FIXME is addressed above
        // for the case where a new meter is sent
        throw new Error('Not implemented; meter cannot be changed.');
        await meters.upsert({id: meterId, serviceType: SERVICE_TYPE});
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

      res.json({success: true, config});
    }));

  // get a keystore config
  app.get(
    routes.keystore,
    cors(),
    _getKeystoreConfig,
    _authorizeZcapInvocation({
      async getExpectedTarget({req}) {
        // expected target is the keystore itself
        return {expectedTarget: req.webkms.keystore.id};
      },
      onError
    }),
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
    _getKeystoreConfig,
    asyncHandler(async (req, res) => {
      const {webkms: {keystore}} = req;
      const keyId = `${keystore.id}/keys/${req.params.keyId}`;
      const moduleApi = await moduleManager.get({id: keystore.kmsModule});
      const keyDescription = await moduleApi.getKeyDescription({keyId});
      res.json(keyDescription);
    }));

  // insert a revocation
  app.options(routes.revocations, cors());
  app.post(
    routes.revocations,
    cors(),
    validate({bodySchema: postRevocationBody}),
    _getKeystoreConfig,
    authorizeZcapRevocation({
      expectedHost: config.server.host,
      getRootController: _getRootController,
      documentLoader,
      async getExpectedTarget({req}) {
        // allow target to be root keystore, main revocations endpoint, *or*
        // zcap-specific revocation endpoint; see ezcap-express for more
        const {webkms: {keystore}} = req;
        const revocations = `${keystore.id}/revocations`;
        const revokeZcap = `${revocations}/` +
          encodeURIComponent(req.params.zcapId);
        return {expectedTarget: [keystore.id, revocations, revokeZcap]};
      },
      suiteFactory() {
        return new Ed25519Signature2020();
      },
      inspectCapabilityChain: helpers.inspectCapabilityChain,
      onError
    }),
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

      // report revocation usage
      _reportRevocationUsage({meterId}).catch(
        error => logger.error(
          `Keystore (${keystore.id}) capability revocation meter ` +
          'usage error.', {error}));

      res.status(204).end();
    }));
});

async function _getRootController({
  req, rootCapabilityId, rootInvocationTarget
}) {
  const kmsBaseUrl = req.protocol + '://' + req.get('host') +
    config['kms-http'].routes.basePath;

  // get controller for the entire KMS
  if(rootInvocationTarget === kmsBaseUrl) {
    throw new Error(`Invalid root invocation target "${kmsBaseUrl}".`);
  }

  // allow cached config to be used if already retrieved
  if(req.webkms && req.webkms.keystore.id === rootInvocationTarget) {
    return req.webkms.keystore.controller;
  }

  // get controller for an individual keystore
  let controller;
  try {
    ({controller} = await storage.get({id: rootInvocationTarget, req}));
  } catch(e) {
    if(e.type === 'NotFoundError') {
      const url = req.protocol + '://' + req.get('host') + req.url;
      throw new Error(
        `Invalid capability identifier "${rootCapabilityId}" ` +
        `for URL "${url}".`);
    }
    throw e;
  }
  return controller;
}

async function _aggregateUsage({meter, signal} = {}) {
  const {id: meterId} = meter;
  return keystores.getStorageUsage({
    meterId, moduleManager, aggregate: _addRevocationUsage, signal
  });
}

async function _addRevocationUsage({config, usage}) {
  // add storage units for revocations associated with the keystore
  const {id: keystoreId} = config;
  const {storageCost} = bedrock.config.kms;
  // if `count` is available, use it to count stored revocations
  if(brZCapStorage.revocations.count) {
    const {count} = await brZCapStorage.revocations.count(
      {rootTarget: keystoreId});
    usage.storage += count * storageCost.revocation;
  }
}

// gets the keystore config for the current request and caches it in
// `req.webkms.keystore`
function createGetKeystoreConfig({routes}) {
  return asyncHandler(async function _getKeystoreConfig(req, res, next) {
    if(!(req && req.webkms)) {
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const keystore = await storage.get({id: keystoreId, req});
      req.webkms = {keystore};
    }
    process.nextTick(next);
  });
}

function _authorizeZcapInvocation({
  getExpectedTarget, getRootController = _getRootController,
  expectedAction, onError
} = {}) {
  return authorizeZcapInvocation({
    expectedHost: config.server.host,
    getRootController,
    documentLoader,
    getExpectedTarget,
    expectedAction,
    inspectCapabilityChain: helpers.inspectCapabilityChain,
    onError,
  });
}

async function _getExpectedKeystoreTarget({req}) {
  // ensure the `configId` matches the request URL (i.e., that the caller
  // POSTed a config with an ID that matches up with the URL to which they
  // POSTed); this is not a security issue if this check is not performed,
  // however, it can help clients debug errors on their end
  const {body: {id: configId}} = req;
  const requestUrl = `${req.protocol}://${req.get('host')}${req.url}`;
  if(configId !== requestUrl) {
    throw new BedrockError(
      'The request URL does not match the configuration ID.',
      'URLMismatchError', {
        // this error will be a `cause` in the onError handler below
        // this httpStatusCode is not operative
        httpStatusCode: 400,
        public: true,
        configId,
        requestUrl,
      });
  }
  return {expectedTarget: configId};
}

function onError({error}) {
  // cause must be a public BedrockError to be surfaced to the HTTP client
  let cause;
  if(error instanceof BedrockError) {
    cause = error;
  } else {
    cause = new BedrockError(
      error.message,
      error.name || 'NotAllowedError', {
        ...error.details,
        public: true,
      });
  }
  throw new BedrockError(
    'Authorization error.', 'NotAllowedError', {
      httpStatusCode: 403,
      public: true,
    }, cause);
}

async function _reportRevocationUsage({meterId}) {
  await meters.use({id: meterId, operations: 1});
}
