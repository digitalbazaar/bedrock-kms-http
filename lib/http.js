/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const {authorizeZcapInvocation} = require('@digitalbazaar/ezcap-express');
const bedrock = require('bedrock');
const BedrockKeystoreConfigStorage = require('./BedrockKeystoreConfigStorage');
const {
  defaultDocumentLoader: documentLoader,
  defaultModuleManager: moduleManager,
  keystores
} = require('bedrock-kms');
const {config, util: {BedrockError}} = bedrock;
const brZCapStorage = require('bedrock-zcap-storage');
const cors = require('cors');
const {
  createMiddleware: createOperationMiddleware,
  generateRandom
} = require('webkms-switch');
const helpers = require('./helpers');
const {meters} = require('bedrock-meter-usage-reporter');
const {validator: validate} = require('./validator');
const {
  // FIXME: consider for removing `getKeystoreQuery` if presently unused
  //getKeystoreQuery,
  postKeystoreBody,
  updateKeystoreConfigBody,
  zcap: zcapSchema
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
  routes.authorizations = `${routes.keystore}/authorizations`;
  routes.keys = `${routes.keystore}/keys`;
  routes.key = `${routes.keys}/:keyId`;
  routes.revocations = `${routes.keystore}/revocations`;

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
    onSuccess: reportOperationUsage
  });

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities, not cookies; CSRF is not possible. */

  // create a new keystore
  app.options(routes.keystores, cors());
  app.post(
    routes.keystores,
    cors(),
    validate({bodySchema: postKeystoreBody}),
    asyncHandler(async (req, res) => {
      const {body: {meterCapability}} = req;
      const serviceType = SERVICE_TYPE;
      const hasAvailable = await meters.hasAvailable({
        meterCapability, resources: {storage: storageCost.keystore}
      });
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

      // add meter
      const {meter: {id: meterId}} = await meters.upsert(
        {meterCapability, serviceType});

      // create a keystore for the controller
      const random = await generateRandom();
      const id = helpers.getKeystoreId({req, localId: random, routes});
      const config = {id, meterId, ...req.body};
      delete config.meterCapability;
      const record = await keystores.insert({config});
      res.status(201).location(id).json(record.config);
    }));

  // FIXME: consider for removal if presently unused
  // get keystore configs by query
  /*app.get(
    routes.keystores,
    cors(),
    // FIXME: add zcap-authorization
    validate({querySchema: getKeystoreQuery}),
    asyncHandler(async (req, res) => {
      const {controller, referenceId} = req.query;
      const query = {'config.referenceId': referenceId};
      const results = await keystores.find(
        {controller, query, fields: {_id: 0, config: 1}});
      // TODO: consider returning only IDs and let other endpoint handle
      // retrieval of full configs

      const filteredResult = results.filter(({config: keystoreConfig}) => {
        const {verified} = helpers.verifyRequestIp({keystoreConfig, req});
        return verified;
      });

      res.json(filteredResult.map(r => r.config));
    }));*/

  // update keystore config
  app.options(routes.keystore, cors());
  app.post(
    routes.keystore,
    cors(),
    validate({bodySchema: updateKeystoreConfigBody}),
    _authorizeZcapInvocation({
      getExpectedTarget: _getExpectedKeystoreTarget,
      onError
    }),
    asyncHandler(async (req, res) => {
      const {body: config} = req;
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      if(keystoreId !== req.body.id) {
        throw new BedrockError(
          'Configuration "id" does not match.',
          'DataError', {
            httpStatusCode: 400,
            public: true,
            expected: keystoreId,
            actual: config.id
          });
      }

      /* Calls to update a keystore config are expected to be infrequent, so
      calling these async functions in serial acceptable as it is the cleanest
      implementation as it prevents unnecessary meter storage / fixing that
      would have to be dealt with later if the calls were optimistically
      performed in parallel instead. */

      // ensure keystore can be retrieved (IP check, etc.)
      await storage.get({id: keystoreId, req});

      // add meter
      const {meterCapability} = config;
      const {meter: {id: meterId}} = await meters.upsert(
        {meterCapability, serviceType: SERVICE_TYPE});

      // use meter ID only
      config.meterId = meterId;
      delete config.meterCapability;

      // the `update` API will not apply the change and will throw if
      // `config.sequence` is not valid, no need to check it here
      await keystores.update({config});

      res.json({success: true, config});
    }));

  // get a keystore config
  app.get(
    routes.keystore,
    cors(),
    _authorizeZcapInvocation({
      getExpectedTarget: _getExpectedKeystoreTarget,
      onError
    }),
    asyncHandler(async (req, res) => {
      const id = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const keystore = await storage.get({id});
      res.json(keystore);
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
  // return a (public) key description
  app.get(
    routes.key,
    cors(),
    asyncHandler(async (req, res) => {
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const keyId = `${keystoreId}/keys/${req.params.keyId}`;
      const keystore = await storage.get({req, id: keystoreId});
      const moduleApi = await moduleManager.get({id: keystore.kmsModule});
      const keyDescription = moduleApi.getKeyDescription({keyId});
      res.json(keyDescription);
    }));

  // insert a revocation
  app.options(routes.revocations, cors());
  app.post(
    routes.revocations,
    cors(),
    validate({bodySchema: zcapSchema}),
    _authorizeZcapInvocation({
      getExpectedTarget: async ({req}) => {
        const keystoreId = helpers.getKeystoreId(
          {req, localId: req.params.keystoreId, routes});
        // ensure keystore can be retrieved
        await storage.get({id: keystoreId});
        return {expectedTarget: [keystoreId, `${keystoreId}/revocations`]};
      },
      onError
    }),
    asyncHandler(async (req, res) => {
      // verify CapabilityDelegation before storing zcap
      const capability = req.body;
      const host = req.get('host');

      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});

      let delegator;
      try {
        const results = await helpers.verifyDelegation(
          {keystoreId, host, capability});
        ({delegator} = results[0].purposeResult);
        delegator = delegator.id || delegator;
      } catch(e) {
        throw new BedrockError(
          'The provided capability delegation is invalid.',
          'DataError', {
            httpStatusCode: 400,
            public: true,
            message: e.message
          }, e);
      }

      // ensure that the invoker of the write capability is the delegator
      // of the capability to be revoked
      const invoker = req.zcap.controller || req.zcap.invoker;
      if(delegator !== invoker) {
        throw new BedrockError('Permission denied.', 'NotAllowedError');
      }

      // FIXME: brZCapStorage needs to support getting a count on stored
      // revocations -- and that count needs to be filtered based on a
      // particular meter

      // record revocation
      await brZCapStorage.revocations.insert({delegator, capability});

      // meter revocation usage
      _reportRevocationUsage({keystoreId}).catch(
        error => logger.error(
          `Keystore (${keystoreId}) capability revocation meter ` +
          'usage error.', {error}));

      res.status(204).end();
    }));
});

async function getRootController({
  req, rootCapabilityId, rootInvocationTarget
}) {
  const kmsBaseUrl = req.protocol + '://' + req.get('host') +
    config['kms-http'].routes.basePath;

  // get controller for the entire KMS
  if(rootInvocationTarget === kmsBaseUrl) {
    // FIXME: return root capability for entire KMS system. See issue #45.
    // FIXME: determine if this will be needed or if a meter zcap would always
    // be provided in these cases -- and this should therefore always throw
    throw new Error('Not Implemented.');
  }

  // get controller for an individual keystore
  let controller;
  try {
    ({controller} = await storage.get({id: rootInvocationTarget}));
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
  const [usage, revocationCount] = await Promise.all([
    keystores.getStorageUsage({meterId, signal}),
    // FIXME: get zcap revocation count associated with this meter
    0
  ]);

  // sum keystore storage and revocation storage
  const {storageCost} = config['kms-http'];
  usage.storage += revocationCount * storageCost.revocation;

  return usage;
}

function _authorizeZcapInvocation({
  getExpectedTarget, expectedAction, onError
} = {}) {
  return authorizeZcapInvocation({
    expectedHost: config.server.host,
    getRootController,
    documentLoader,
    getExpectedTarget,
    expectedAction,
    logger,
    onError,
  });
}

async function _getExpectedKeystoreTarget({req}) {
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

async function _reportRevocationUsage({keystoreId}) {
  const keystore = await storage.get({id: keystoreId});
  meters.use({id: keystore.meterId, operations: 1});
}
