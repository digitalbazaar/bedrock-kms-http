/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
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
const URL = require('url').URL;
const {generateRandom} = require('webkms-switch');
const helpers = require('./helpers');
require('bedrock-express');

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
    //validate('bedrock-kms-http.keystore'),
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
      _verifyHost(id);

      // create a keystore for the controller
      const {config} = await keystores.insert({config: {id, ...req.body}});
      res.status(201).location(id).json(config);
    }));

  // get keystore configs by query
  app.get(
    routes.keystores,
    cors(),
    createMiddleware({strategy: 'session'}),
    // TODO: implement query validator
    //validate('bedrock-kms-http.keystore.foo'),
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
      if(!controller) {
        throw new BedrockError(
          'Query not supported; a "controller" must be specified.',
          'NotSupportedError', {public: true, httpStatusCode: 400});
      }
      if(!referenceId) {
        // query for all keystores controlled by controller not implemented yet
        // TODO: implement
        throw new BedrockError(
          'Query not supported; a "referenceId" must be specified.',
          'NotSupportedError', {public: true, httpStatusCode: 400});
      }
      const query = {'config.referenceId': referenceId};
      const results = await keystores.find(
        {controller, query, fields: {_id: 0, config: 1}});
      // TODO: consider returning only IDs and let other endpoint handle
      // retrieval of full configs
      res.json(results.map(r => r.config));
    }));

  // TODO: implement `update` for keystore config

  // host application-based key recovery
  app.post(
    `${routes.keystore}/recover`,
    // Note: No CORS! Must be done on the host site directly.
    createMiddleware({strategy: 'session'}),
    // TODO: add validator that requires security `@context` and `controller`
    // in post body
    //validate('bedrock-kms-http.recovery'),
    asyncHandler(async (req, res) => {
      // FIXME: rework to use `controller` specified in `account` associated
      // with session ... right now any authenticated user can add a controller
      // to any keystore with `allowedHost` as a controller; instead only
      // those controllers listed in `account` should be added/removed to
      // the keystore controller here... needs tighter integration with
      // an account both for simplicity and security
      // FIXME: in non-proxy mode, this code should determine what config
      // changes to make and then post them to the non-proxied update
      // config endpoint using `sequence` to ensure atomicity of transaction

      const id = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      _verifyHost(id);

      const {config} = await keystores.get({id});

      // ensure `allowedHost` is an invoker
      let {invoker} = config;
      if(!Array.isArray(invoker)) {
        invoker = [invoker];
      }
      if(!invoker.includes(`https://${bedrock.config.kms.allowedHost}`)) {
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 400,
          public: true,
        });
      }

      // get new controller from body
      const {controller} = req.body;
      // update config
      config.sequence++;
      const {controller: oldController} = config;
      config.controller = controller;
      // replace existing controller with new one
      config.invoker = config.invoker.map(
        x => x === oldController ? controller : x);
      if(Array.isArray(config.delegator)) {
        config.delegator = config.delegator.map(
          x => x === oldController ? controller : x);
      } else if(config.delegator === oldController) {
        config.delegator = controller;
      }
      await keystores.update({config});
      res.json(config);
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
      _verifyHost(id);
      const {config} = await keystores.get({id});
      res.json(config);
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
      _verifyHost(id);
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
      const result = await _handleOperation({req});
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
    // TODO: add zcap validator
    //validate('bedrock-kms-http.zcap'),
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

async function _handleOperation({req, expectedRootCapability, keystoreId}) {
  const host = req.get('host');
  const url = `https://${host}${req.originalUrl}`;
  const {method, headers, body: operation} = req;
  const result = await validateOperation({
    url, method, headers,
    operation,
    expectedHost: config.kms.allowedHost,
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
  if(operation.type === 'GenerateKeyOperation') {
    // disallow generating a key with a controller that is different from the
    // keystore's controller
    const {config} = await keystores.get({id: keystoreId});
    const {invocationTarget: {controller}} = operation;
    if(controller !== undefined && controller !== config.controller) {
      throw new BedrockError(
        `Invalid KMS operation; key controller (${controller}) must match ` +
        `keystore controller (${config.controller}).`, 'DataError', {
          httpStatusCode: 400,
          public: true
        });
    }
    const random = await generateRandom();
    operation.invocationTarget.id = `${url}/${random}`;
  }
  return runOperation({operation});
}

function _verifyHost(url) {
  const {allowedHost} = config.kms;
  const parsed = new URL(url);
  if(parsed.host !== allowedHost) {
    throw new BedrockError('Permission denied.', 'NotAllowedError', {
      httpStatusCode: 400,
      public: true,
    });
  }
}
