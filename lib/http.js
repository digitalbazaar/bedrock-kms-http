/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const {
  defaultDocumentLoader,
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
const {verifyCapabilityInvocation} = require('http-signature-zcap-verify');
const jsigs = require('jsonld-signatures');
const {extendContextLoader, SECURITY_CONTEXT_V2_URL} = jsigs;
const {Ed25519Signature2018} = jsigs.suites;
const {CapabilityDelegation} = require('ocapld');
const {generateRandom} = require('web-kms-switch');
require('bedrock-express');

// load config defaults
require('./config');

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

  function _getKeystoreId({host, req, localId}) {
    if(!host) {
      host = req.get('host');
    }
    return `https://${host}${routes.keystores}/${localId}`;
  }

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

      // TODO: check `config.kms.allowedHost` list as sanity check (user
      // sets this anyway)
      const random = await generateRandom();
      const id = _getKeystoreId({req, localId: random});

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

  // get a keystore config
  app.get(
    routes.keystore,
    cors(),
    // TODO: consider making this zcap authorized instead
    createMiddleware({strategy: 'session'}),
    asyncHandler(async (req, res) => {
      // TODO: check `config.kms.allowedHost` as sanity check (user
      // sets this anyway)
      const id = _getKeystoreId({req, localId: req.params.keystoreId});
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
  app.get(
    routes.zcaps,
    cors(),
    asyncHandler(async (req, res) => {
      // compute invocation target
      // TODO: check `config.kms.allowedHost` list as sanity check (user
      // sets this anyway)
      const host = req.get('host');
      const id = `https://${host}${req.originalUrl}`;
      const result = _getInvocationTarget({host, url: id});
      if(!result) {
        // invalid root zcap ID
        throw new BedrockError(
          'Keystore capability not found.',
          'NotFoundError',
          {id, httpStatusCode: 404, public: true});
      }
      const {target, keystoreId} = result;

      // dynamically generate root capability for target
      const zcap = await _generateRootCapability({id, target, keystoreId});
      res.json(zcap);
    }));

  // invoke a generate key KMS operation to generate a new key
  app.post(
    routes.keys,
    // CORs is safe because authorization uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    asyncHandler(async (req, res) => {
      // expect root capability to be `.../zcaps/keys`
      const keystoreId = _getKeystoreId({req, localId: req.params.keystoreId});
      const expectedRootCapability = `${keystoreId}/zcaps/keys`;
      const result = await _handleOperation({
        req, expectedRootCapability, keystoreId
      });
      res.json(result);
    }));

  // invoke KMS operation on an existing key
  app.post(
    routes.key,
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
      const keystoreId = _getKeystoreId({req, localId: req.params.keystoreId});
      const id = `${keystoreId}/keys/${req.params.keyId}`;
      const {key} = await keyDescriptionStorage.get({id});
      res.json(key);
    }));

  // insert an authorization
  app.options(routes.authorizations, cors());
  app.post(
    routes.authorizations,
    // CORs is safe because authorization uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    // TODO: add zcap validator
    //validate('bedrock-kms-http.zcap'),
    asyncHandler(async (req, res) => {
      // check authorization
      const keystoreId = _getKeystoreId(
        {req, localId: req.params.keystoreId});
      const expectedTarget = `${keystoreId}/authorizations`;
      const expectedRootCapability = `${keystoreId}/zcaps/authorizations`;
      const {invoker} = await _authorize({
        req, expectedTarget, expectedRootCapability,
        expectedAction: 'write'
      });

      // verify CapabilityDelegation before storing zcap
      const controller = invoker;
      const capability = req.body;
      const host = req.get('host');
      await _verifyDelegation({keystoreId, host, controller, capability});
      await brZCapStorage.authorizations.insert({controller, capability});
      res.status(204).end();
    }));

  // get one or more authorizations
  app.get(
    routes.authorizations,
    asyncHandler(async (req, res) => {
      // check authorization
      const keystoreId = _getKeystoreId(
        {req, localId: req.params.keystoreId});
      const expectedTarget = `${keystoreId}/authorizations`;
      const expectedRootCapability = `${keystoreId}/zcaps/authorizations`;
      const {invoker} = await _authorize({
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
      const keystoreId = _getKeystoreId(
        {req, localId: req.params.keystoreId});
      const expectedTarget = `${keystoreId}/authorizations`;
      const expectedRootCapability = `${keystoreId}/zcaps/authorizations`;
      const {invoker} = await _authorize({
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
    getInvokedCapability: createGetInvokedCapability(host),
    documentLoader: createRootCapabilityLoader(host)
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
    if(controller !== config.controller) {
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

// TODO: a lot of helper code here is in common w/ bedrock-data-hub-storage,
// consider refactoring to share it

async function _authorize({
  req, expectedTarget, expectedRootCapability, expectedAction
}) {
  const host = req.get('host');
  const url = `https://${host}${req.originalUrl}`;
  const {method, headers} = req;
  const result = await verifyCapabilityInvocation({
    url, method, headers,
    getInvokedCapability: createGetInvokedCapability(host),
    documentLoader: createRootCapabilityLoader(host),
    expectedHost: config.server.host,
    expectedTarget, expectedRootCapability, expectedAction,
    // TODO: support RsaSignature2018 and other suites?
    suite: [new Ed25519Signature2018()]
  });
  if(!result.verified) {
    throw new BedrockError(
      'Permission denied.', 'NotAllowedError', {
        httpStatusCode: 400,
        public: true
      }, result.error);
  }
  return {
    valid: result.verified,
    ...result
  };
}

async function _verifyDelegation({keystoreId, host, controller, capability}) {
  // `delegatedBy` must be a root delegator; it is not permitted to delegate
  // storing delegated capabilities
  const {config} = await keystores.get({id: keystoreId});
  let delegator = config.delegator || config.controller;
  if(!Array.isArray(delegator)) {
    delegator = [delegator];
  }
  if(!delegator.includes(controller)) {
    throw new BedrockError(
      'Delegated capabilities may only be stored by a root delegator.',
      'NotAllowedError', {
        public: true,
        httpStatusCode: 400,
        controller,
        delegator
      });
  }

  const documentLoader = extendContextLoader(async url => {
    // if `id` starts with `<keystoreId>/keys/`, assume zcap is a key
    if(url.startsWith(`${keystoreId}/keys/`)) {
      // dynamically generate zcap for root capability
      const {key} = await keyDescriptionStorage.get({id: url});
      return {
        contextUrl: null,
        documentUrl: url,
        document: key
      };
    }

    // check if URL is a root zcap w/ a different invocation target
    const result = _getInvocationTarget({host, url});
    if(result) {
      // dynamically generate zcap for root capability
      const {target, keystoreId} = result;
      return {
        contextUrl: null,
        documentUrl: url,
        document: await _generateRootCapability({id: url, target, keystoreId})
      };
    }

    return defaultDocumentLoader(url);
  });

  const {verified, error} = await jsigs.verify(capability, {
    suite: new Ed25519Signature2018(),
    purpose: new CapabilityDelegation({
      suite: new Ed25519Signature2018()
    }),
    documentLoader,
    compactProof: false
  });
  if(!verified) {
    throw error;
  }
}

// wrap document loader to always generate root zcap from keystore config
// description in storage
function createRootCapabilityLoader(host) {
  return async function rootCapabilityLoader(url) {
    const result = _getInvocationTarget({host, url});
    if(result) {
      // dynamically generate zcap for root capability
      const {target, keystoreId} = result;
      return {
        contextUrl: null,
        documentUrl: url,
        document: await _generateRootCapability({id: url, target, keystoreId})
      };
    }
    return defaultDocumentLoader(url);
  };
}

function createGetInvokedCapability(host) {
  return async function getInvokedCapability({id, expectedTarget}) {
    try {
      // if `id` matches `expectedTarget`, assume zcap is a key
      if(id === expectedTarget) {
        // dynamically generate zcap for root capability
        const {key} = await keyDescriptionStorage.get({id});
        return key;
      }

      // if the capability is a root zcap generated by this server then its
      // `id` will map to an invocation target; if so, dynamically generate the
      // zcap as it is the root authority which is automatically authorized
      const result = _getInvocationTarget({host, url: id});
      if(result) {
        // dynamically generate zcap for root capability
        const {target, keystoreId} = result;
        return _generateRootCapability({id, target, keystoreId});
      }

      // otherwise, must get capability from authorizations storage
      const {authorization} = await brZCapStorage.authorizations.get({
        id,
        invocationTarget: expectedTarget
      });
      return authorization.capability;
    } catch(e) {
      if(e.name === 'NotFoundError') {
        throw new BedrockError(
          'Permission denied.', 'NotAllowedError', {
            httpStatusCode: 400,
            public: true
          }, e);
      }
      throw e;
    }
  };
}

async function _generateRootCapability(
  {id, target, keystoreId, config = null}) {
  if(!config) {
    ({config} = await keystores.get({id: keystoreId}));
  }
  // dynamically generate zcap for root capability
  return {
    '@context': SECURITY_CONTEXT_V2_URL,
    id,
    invocationTarget: target,
    controller: config.controller,
    invoker: config.invoker,
    delegator: config.delegator
  };
}

function _getInvocationTarget({host, url}) {
  // look for `/kms/keystores/<keystoreId>/zcaps/`
  const cfg = config['kms-http'];
  const baseKeystoreUrl = `https://${host}${cfg.routes.basePath}/keystores/`;
  let idx = url.indexOf(baseKeystoreUrl);
  if(idx !== 0) {
    return null;
  }

  // skip keystore ID
  const keystoreIdIdx = baseKeystoreUrl.length;
  idx = url.indexOf('/', keystoreIdIdx);
  if(idx === -1) {
    return null;
  }
  const keystoreId = `${baseKeystoreUrl}${url.substring(keystoreIdIdx, idx)}`;

  // skip `zcaps`
  idx = url.indexOf('zcaps/', idx + 1);
  if(idx === -1) {
    return null;
  }

  // valid root zcap invocation targets:
  // `/kms/keystores/<keystoreId>/keys`
  // `/kms/keystores/<keystoreId>/authorizations`
  const path = url.substr(idx + 6 /* 'zcaps/'.length */);
  if(!['keys', 'authorizations'].includes(path)) {
    return null;
  }

  // return invocation target for the given root zcap URL
  return {
    target: `${keystoreId}/${path}`,
    keystoreId
  };
}
