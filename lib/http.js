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
const {createMiddleware} = require('bedrock-passport');
const brZCapStorage = require('bedrock-zcap-storage');
const cors = require('cors');
const {
  createMiddleware: createOperationMiddleware,
  generateRandom
} = require('webkms-switch');
const helpers = require('./helpers');
const {validator: validate} = require('./validator');
const {
  getKeystoreQuery,
  postKeystoreBody,
  updateKeystoreConfigBody,
  zcap: zcapSchema
} = require('../schemas/bedrock-kms-http');
const storage = new BedrockKeystoreConfigStorage();
const logger = require('./logger');

/* FIXME:
1. Call bedrock-kms usage API whenever any key operation is performed and
  whenever a key is created.
2. On keystore creation, require a zcap that can hit a usage limitation HTTP
  API. This usage limitation HTTP API can have a custom implementation to
  provide arbitrary (well, given the primitives of key ops and storage size)
  limitations for keystore usage.
*/

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];
  const routes = {...cfg.routes};
  // WebKMS paths are fixed off of the base path per the spec
  routes.keystores = `${routes.basePath}/keystores`;
  routes.keystore = `${routes.keystores}/:keystoreId`;
  routes.authorizations = `${routes.keystore}/authorizations`;
  routes.keys = `${routes.keystore}/keys`;
  routes.key = `${routes.keys}/:keyId`;
  routes.revocations = `${routes.keystore}/revocations`;

  // create middleware for handling KMS operations
  const handleOperation = createOperationMiddleware({
    storage, moduleManager, documentLoader,
    expectedHost: config.server.host,
    inspectCapabilityChain: helpers.inspectCapabilityChain
  });

  // create a new keystore
  app.post(
    routes.keystores,
    validate({bodySchema: postKeystoreBody}),
    asyncHandler(async (req, res) => {
      const {body: {meterCapability}} = req;
      const hasAvailable = await brMeterClient.usage.hasAvailable(
        {meterCapability, storage: cfg.storageCost.keystore});
      if(!hasAvailable) {
        // insufficient remaining storage
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 403,
          public: true,
        });
      }

      // FIXME: upsert meter zcap (we can presume the storage for the meter
      // itself is already accounted for/coered since meter is valid); it
      // should only be added if the zcap is the most recent/last to expire
      const {meter: {id: meterId}} = await brMeterClient.meters.add(
        {meterCapability});

      // create a keystore for the controller
      const random = await generateRandom();
      const id = helpers.getKeystoreId({req, localId: random, routes});
      const config = {id, meterId, ...req.body};
      delete config.meterCapability;
      const record = await keystores.insert({config});
      res.status(201).location(id).json(record.config);
    }));

  // get keystore configs by query
  app.get(
    routes.keystores,
    cors(),
    // FIXME: use zcap-authorization instead
    createMiddleware({strategy: 'session'}),
    validate({querySchema: getKeystoreQuery}),
    asyncHandler(async (req, res) => {
      // FIXME: remove once zcap authz is implemented for keystore query

      // authentication should only be disabled in a setup where keystore
      // requests are proxied from authorized apps to the KMS
      if(cfg.requireAuthentication && !req.user) {
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 400,
          public: true,
        });
      }

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
    }));

  // update keystore config
  app.post(
    `${routes.keystore}`,
    _authorizeZcapInvocation({
      getExpectedTarget: _getExpectedKeystoreTarget,
      onError
    }),
    validate({bodySchema: updateKeystoreConfigBody}),
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

      const {config: keystoreConfig} = await keystores.get({id: keystoreId});
      const {verified} = helpers.verifyRequestIp({keystoreConfig, req});
      if(!verified) {
        throw new BedrockError(
          'Permission denied. Source IP is not allowed.', 'NotAllowedError', {
            httpStatusCode: 403,
            public: true,
          });
      }

      // the `update` API will not apply the change if `config.sequence` is
      // not valid, no need to check it here
      await keystores.update({config});

      res.json({success: true, config});
    }));

  // get a keystore config
  app.options(routes.keystore, cors());
  app.get(
    routes.keystore,
    cors(),
    // FIXME: make this zcap-authorized instead
    createMiddleware({strategy: 'session'}),
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
    // CORS is safe because authorization uses HTTP signatures + capabilities,
    // not cookies; not possible to use CSRF to generate a key
    cors(),
    handleOperation);

  // invoke KMS operation on an existing key
  app.options(routes.key, cors());
  app.post(
    routes.key,
    // CORS is safe because authorization uses HTTP signatures + capabilities,
    // not cookies; not possible to use CSRF to run a key operation
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
    // CORs is safe because revocation uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    validate({bodySchema: zcapSchema}),
    _authorizeZcapInvocation({
      getExpectedTarget: async ({req}) => {
        const keystoreId = helpers.getKeystoreId(
          {req, localId: req.params.keystoreId, routes});
        // ensure keystore can be retrieved
        await storage.get({id: keystoreId});
        return {expectedTarget: [keystoreId, `{$keystoreId}/revocations`]};
      },
      onError
    }),
    asyncHandler(async (req, res) => {
      // verify CapabilityDelegation before storing zcap
      const capability = req.body;
      const host = req.get('host');

      let delegator;
      try {
        const keystoreId = helpers.getKeystoreId(
          {req, localId: req.params.keystoreId, routes});
        const results = await helpers.verifyDelegation(
          {keystoreId, host, capability});
        ({delegator} = results[0].purposeResult);
        delegator = typeof _delegator === 'string' ? delegator : delegator.id;
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
      await brZCapStorage.revocations.insert({delegator, capability});
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
    'ZCAP authorization error.', 'NotAllowedError', {
      httpStatusCode: 403,
      public: true,
    }, cause);
}
