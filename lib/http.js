/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
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
  createOperationMiddleware,
  generateRandom
} = require('webkms-switch');
const {CryptoLD} = require('crypto-ld');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
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

// create `getVerifier` hook for verifying zcap invocation HTTP signatures
// FIXME: determine if this can be pushed to the top-level or not
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

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
  routes.revocations = `${routes.keystore}/revocations/:revocationId`;

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
    expectedHost: config.server.host, getVerifier,
    inspectCapabilityChain: helpers.inspectCapabilityChain,
    onError, onSuccess: reportOperationUsage, suiteFactory
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
    // now that meter information has been obtained, authorize zcap invocation
    authorizeZcapInvocation({
      documentLoader,
      async getExpectedValues() {
        const expectedHost = config.server.host;
        return {
          host: expectedHost,
          // expect root invocation target to match this route; the root zcap
          // will have a controller dynamically set to the controller of the
          // meter used as below in `getRootController`
          rootInvocationTarget: `https://${expectedHost}${routes.keystores}`
        };
      },
      async getRootController({req}) {
        // use meter's controller as the root controller for the keystore
        // creation endpoint
        return req.meterCheck.meter.controller;
      },
      getVerifier,
      inspectCapabilityChain: helpers.inspectCapabilityChain,
      onError,
      suiteFactory
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
    // the meter; otherwise set it to be that of the keystore
    authorizeKeystoreZcapInvocation(),
    asyncHandler(async (req, res) => {
      const {body: config} = req;
      const {keystore: existingConfig} = req.webkms;
      if(existingConfig.id !== req.body.id) {
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

      res.json({success: true, config});
    }));

  // get a keystore config
  app.get(
    routes.keystore,
    cors(),
    _getKeystoreConfig,
    authorizeKeystoreZcapInvocation(),
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
      documentLoader,
      expectedHost: config.server.host,
      async getRootController({req}) {
        // this will always be present based on where this middleware is used
        return req.webkms.keystore.controller;
      },
      getVerifier,
      inspectCapabilityChain: helpers.inspectCapabilityChain,
      onError,
      suiteFactory
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

// creates middleware for keystore route authz checks
function authorizeKeystoreZcapInvocation() {
  return authorizeZcapInvocation({
    documentLoader,
    async getExpectedValues({req}) {
      return {
        host: config.server.host,
        rootInvocationTarget: req.webkms.keystore.id
      };
    },
    async getRootController({req}) {
      // this will always be present based on where this middleware is used
      return req.webkms.keystore.controller;
    },
    getVerifier,
    inspectCapabilityChain: helpers.inspectCapabilityChain,
    onError,
    suiteFactory
  });
}

// hook used to verify zcap invocation HTTP signatures
async function getVerifier({keyId, documentLoader}) {
  const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
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

// hook used to create suites for verifying zcap delegation chains
async function suiteFactory() {
  return new Ed25519Signature2020();
}

async function _reportRevocationUsage({meterId}) {
  await meters.use({id: meterId, operations: 1});
}
