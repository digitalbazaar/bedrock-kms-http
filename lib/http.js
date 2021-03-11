/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const {
  runOperation,
  validateOperation,
  keystores,
  keyDescriptionStorage
} = require('bedrock-kms');
const {config, util: {BedrockError}} = bedrock;
const {createMiddleware} = require('bedrock-passport');
const brZCapStorage = require('bedrock-zcap-storage');
const cors = require('cors');
const database = require('bedrock-mongodb');
const {generateRandom} = require('webkms-switch');
const helpers = require('./helpers');
const {validator: validate} = require('./validator');
const {
  getKeystoreQuery,
  postKeystoreBody,
  updateKeystoreConfigBody,
  zcap: zcapSchema
} = require('../schemas/bedrock-kms-http');
const {authorizeZcapInvocation} = require('@digitalbazaar/ezcap-express');
const didIo = require('did-io');
const {documentLoader} = require('bedrock-jsonld-document-loader');
const logger = require('./logger');

// Config did-io to support did:key and did:v1 drivers
didIo.use('key', require('did-method-key').driver());
// FIXME: Remove the need to specify driver mode. See issue #44
didIo.use('v1', require('did-veres-one').driver({mode: 'test'}));

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];
  const routes = {...cfg.routes};
  // Web KMS paths are fixed off of the base path
  routes.keystores = `${routes.basePath}/keystores`;
  routes.keystore = `${routes.keystores}/:keystoreId`;
  routes.authorizations = `${routes.keystore}/authorizations`;
  routes.keys = `${routes.keystore}/keys`;
  routes.key = `${routes.keys}/:keyId`;
  routes.zcaps = `${routes.keystore}/zcaps`;

  // TODO: endpoints for creating and deleting keystores will only use
  // session-based auth and check that an account exists on the system
  // that is proxying to the KMS, the KMS itself does not authN/authZ check,
  // assuming this was handled by the application that proxied to it...
  // the reasoning for this should be explained: creating a keystore requires
  // SPAM prevention, which the application must handle (e.g., via account
  // creation)...
  // the keystore configs should have a controller that is (typically) a
  // DID (e.g., did:key, did:v1) but may also have invoker and
  // delegator fields that include that DID and other DIDs to allow for
  // key recovery; all other endpoints use zcaps

  // register a new keystore
  app.post(
    routes.keystores,
    createMiddleware({strategy: 'session'}),
    validate({bodySchema: postKeystoreBody}),
    asyncHandler(async (req, res) => {
      // TODO: perhaps the proxy option should be triggered via `cfg.proxy`
      // with different routes being configured entirely

      // FIXME: any account can create any number of keystores, this should be
      // ... limited but must be done by the application not the KMS server

      // authentication should only be disabled in a setup where keystore
      // requests are proxied from authorized apps to the KMS
      if(cfg.requireAuthentication && !req.user) {
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 400,
          public: true,
        });
      }

      const random = await generateRandom();
      const id = helpers.getKeystoreId({req, localId: random, routes});

      // create a keystore for the controller
      const {config} = await keystores.insert({config: {id, ...req.body}});
      res.status(201).location(id).json(config);
    }));

  // get keystore configs by query
  app.get(
    routes.keystores,
    cors(),
    createMiddleware({strategy: 'session'}),
    validate({querySchema: getKeystoreQuery}),
    asyncHandler(async (req, res) => {
      // FIXME: any account can search for any controller's keystore configs
      // ... should this should prevented but must be implemented by the
      // ... application not the KMS server

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
    _authorizeZcapInvocation(),
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
    // TODO: consider making this zcap authorized instead
    createMiddleware({strategy: 'session'}),
    asyncHandler(async (req, res) => {
      const id = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});

      const {config: keystoreConfig} = await keystores.get({id});

      const {verified} = helpers.verifyRequestIp({keystoreConfig, req});
      if(!verified) {
        throw new BedrockError(
          'Permission denied. Source IP is not allowed.', 'NotAllowedError', {
            httpStatusCode: 403,
            public: true,
          });
      }

      res.json(keystoreConfig);
    }));

  // TODO: review before future implementation...
  // TODO: add authorizations endpoint; include an authorization that allows
  // a special action: key recovery that will change the `controller` on all
  // keys marked with `controller: X` to `controller: Y`.
  // TODO: add endpoint for controller recovery/figure out what endpoint to
  // post to... that will:
  // 1. ensure zcap invocation w/recovery action is authorized
  // 2. accept a payload with old controller and new controller
  // 3. update all key descriptions with the old controller to the new one
  // 4. figure out if `invoker`/`delegator` fields are used/need updating

  // get a root capability for a keystore resource
  app.options(routes.zcaps, cors());
  app.get(
    routes.zcaps,
    cors(),
    asyncHandler(async (req, res) => {
      // compute invocation target
      const host = req.get('host');
      const id = `https://${host}${req.originalUrl}`;

      const result = helpers.getInvocationTarget({host, url: id});
      if(!result) {
        // invalid root zcap ID
        throw new BedrockError(
          'Keystore capability not found.',
          'NotFoundError',
          {id, httpStatusCode: 404, public: true});
      }
      const {target, keystoreId} = result;

      // dynamically generate root capability for target
      const zcap = await helpers.generateRootCapability(
        {id, target, keystoreId});

      res.json(zcap);
    }));

  // invoke a generate key KMS operation to generate a new key
  app.options(routes.keys, cors());
  app.post(
    routes.keys,
    // CORs is safe because authorization uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    asyncHandler(async (req, res) => {
      // expect root capability to be `.../zcaps/keys`
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const expectedRootCapability = `${keystoreId}/zcaps/keys`;
      const result = await _handleOperation({
        req, expectedRootCapability, keystoreId
      });
      res.json(result);
    }));

  // invoke KMS operation on an existing key
  app.options(routes.key, cors());
  app.post(
    routes.key,
    cors(),
    asyncHandler(async (req, res) => {
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const result = await _handleOperation({keystoreId, req});
      res.json(result);
    }));

  // TODO: consider whether this should be exposed w/o authorization or not
  // return a (public) key description
  app.get(
    routes.key,
    cors(),
    asyncHandler(async (req, res) => {
      // dynamically generate zcap for root capability
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const id = `${keystoreId}/keys/${req.params.keyId}`;
      const {key} = await keyDescriptionStorage.get({id});
      res.json(key);
    }));

  // insert an authorization
  app.post(
    routes.authorizations,
    // CORs is safe because authorization uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    validate({bodySchema: zcapSchema}),
    asyncHandler(async (req, res) => {
      // check authorization
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const expectedTarget = `${keystoreId}/authorizations`;
      const expectedRootCapability = `${keystoreId}/zcaps/authorizations`;
      const {invoker} = await helpers.authorize({
        req, expectedTarget, expectedRootCapability,
        expectedAction: 'write'
      });

      // verify CapabilityDelegation before storing zcap
      const controller = invoker;
      const capability = req.body;
      const host = req.get('host');
      await helpers.verifyDelegation({keystoreId, host, capability});
      await brZCapStorage.authorizations.insert({controller, capability});
      res.status(204).end();
    }));

  // get one or more authorizations
  app.options(routes.authorizations, cors());
  app.get(
    routes.authorizations,
    cors(),
    asyncHandler(async (req, res) => {
      // check authorization
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const expectedTarget = `${keystoreId}/authorizations`;
      const expectedRootCapability = `${keystoreId}/zcaps/authorizations`;
      const {invoker} = await helpers.authorize({
        req, expectedTarget, expectedRootCapability,
        expectedAction: 'read'
      });

      const {id} = req.query;
      if(id) {
        const {authorization} = await brZCapStorage.authorizations.get(
          {id, controller: invoker});
        const {capability} = authorization;
        res.json(capability);
      } else {
        const query = {controller: database.hash(invoker)};
        const results = await brZCapStorage.authorizations.find(
          {query, fields: {_id: 0, capability: 1}});
        res.json(results.map(r => r.capability));
      }
    }));

  // delete an authorization
  app.delete(
    routes.authorizations,
    // CORs is safe because authorization uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    asyncHandler(async (req, res) => {
      // check authorization
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const expectedTarget = `${keystoreId}/authorizations`;
      const expectedRootCapability = `${keystoreId}/zcaps/authorizations`;
      const {invoker} = await helpers.authorize({
        req, expectedTarget, expectedRootCapability,
        expectedAction: 'write'
      });

      // require invoker to be a root delegator
      const {config} = await keystores.get({id: keystoreId});
      let delegator = config.delegator || config.controller;
      if(!Array.isArray(delegator)) {
        delegator = [delegator];
      }
      if(!delegator.includes(invoker)) {
        throw new BedrockError(
          'Delegated capabilities may only be removed by a root delegator.',
          'NotAllowedError', {
            public: true,
            httpStatusCode: 400,
            invoker,
            delegator
          });
      }
      const {id} = req.query;
      const removed = await brZCapStorage.authorizations.remove(
        {controller: invoker, id});
      if(removed) {
        res.status(204).end();
      } else {
        res.status(404).end();
      }
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
    ({config: {controller}} = await keystores.get({id: rootInvocationTarget}));
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

function _authorizeZcapInvocation({expectedTarget, expectedAction} = {}) {
  return authorizeZcapInvocation({
    expectedHost: config.server.host,
    getRootController,
    documentLoader: _documentLoader,
    expectedTarget,
    expectedAction,
    logger,
  });
}

async function _handleOperation({req, expectedRootCapability, keystoreId}) {
  const host = req.get('host');
  const url = `https://${host}${req.originalUrl}`;
  const {method, headers, body: operation} = req;
  const result = await validateOperation({
    url, method, headers,
    operation,
    // this value is passed down to http-signature-zcap-verify
    // where the `host` header is compared to the expectedHost value
    expectedHost: config.server.host,
    expectedRootCapability,
    getInvokedCapability: helpers.createGetInvokedCapability({host}),
    inspectCapabilityChain: helpers.inspectCapabilityChain,
    documentLoader: helpers.createCapabilityLoader({host, expectedTarget: url})
  });
  if(!result.valid) {
    if(result.error instanceof SyntaxError) {
      throw new BedrockError(
        'Invalid KMS operation.', 'DataError', {
          httpStatusCode: 400,
          public: true
        }, result.error);
    }
    throw new BedrockError(
      'Permission denied.', 'NotAllowedError', {
        httpStatusCode: 400,
        public: true
      }, result.error);
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

  if(operation.type === 'GenerateKeyOperation') {
    // disallow generating a key with a controller that is different from the
    // keystore's controller
    const {invocationTarget: {controller}} = operation;
    if(controller !== undefined && controller !== keystoreConfig.controller) {
      throw new BedrockError(
        `Invalid KMS operation; key controller (${controller}) must match ` +
        `keystore controller (${keystoreConfig.controller}).`, 'DataError', {
          httpStatusCode: 400,
          public: true
        });
    }
    const random = await generateRandom();
    operation.invocationTarget.id = `${url}/${random}`;
  }
  return runOperation({operation});
}

// Note: for dereferencing `did:` URLs
async function _documentLoader(url) {
  let document;
  if(url.startsWith('did:')) {
    document = await didIo.get({did: url, forceConstruct: true});
    // FIXME: Remove the startsWith() logic once did-io.get() return signature
    // is updated.
    if(url.startsWith('did:v1:')) {
      document = document.doc;
    }
    return {
      contextUrl: null,
      documentUrl: url,
      document
    };
  }

  // finally, try the bedrock document loader
  return documentLoader(url);
}
