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
const brZCapStorage = require('bedrock-zcap-storage');
const {createOperationMiddleware} = require('webkms-switch');
const {config, util: {BedrockError}} = bedrock;
const {CryptoLD} = require('crypto-ld');
const {
  defaultDocumentLoader: documentLoader,
  defaultModuleManager: moduleManager
} = require('bedrock-kms');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
const helpers = require('./helpers');
const {reportOperationUsage} = require('./metering');

const storage = new BedrockKeystoreConfigStorage();

// create `getVerifier` hook for verifying zcap invocation HTTP signatures
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

// creates middleware to get the keystore config for the current request and
// caches it in `req.webkms.keystore`
exports.createGetKeystoreConfig = function({routes}) {
  return asyncHandler(async function _getKeystoreConfig(req, res, next) {
    if(!req.webkms) {
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const keystore = await storage.get({id: keystoreId, req});
      req.webkms = {keystore};
    }
    next();
  });
};

// creates middleware for handling KMS operations
exports.createKmsOperationMiddleware = function() {
  return createOperationMiddleware({
    storage, moduleManager, documentLoader,
    expectedHost: config.server.host, getVerifier,
    inspectCapabilityChain,
    onError, onSuccess: reportOperationUsage, suiteFactory
  });
};

// calls ezcap-express's authorizeZcapInvocation w/constant params, exposing
// only those params that change in this module
exports.authorizeZcapInvocation = function({
  getExpectedValues, getRootController
}) {
  return authorizeZcapInvocation({
    documentLoader, getExpectedValues, getRootController,
    getVerifier,
    inspectCapabilityChain,
    onError,
    suiteFactory
  });
};

// creates middleware for keystore route authz checks
exports.authorizeKeystoreZcapInvocation = function() {
  return exports.authorizeZcapInvocation({
    async getExpectedValues({req}) {
      return {
        host: config.server.host,
        rootInvocationTarget: req.webkms.keystore.id
      };
    },
    async getRootController({req}) {
      // this will always be present based on where this middleware is used
      return req.webkms.keystore.controller;
    }
  });
};

// creates middleware for revocation of zcaps for keystores
exports.authorizeZcapRevocation = function() {
  return authorizeZcapRevocation({
    documentLoader,
    expectedHost: config.server.host,
    async getRootController({req}) {
      // this will always be present based on where this middleware is used
      return req.webkms.keystore.controller;
    },
    getVerifier,
    inspectCapabilityChain,
    onError,
    suiteFactory
  });
};

// hook used to verify zcap invocation HTTP signatures
async function getVerifier({keyId, documentLoader}) {
  const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}

async function inspectCapabilityChain({
  capabilityChain, capabilityChainMeta
}) {
  // if capability chain has only root, there's nothing to check as root
  // zcaps cannot be revoked
  if(capabilityChain.length === 1) {
    return {valid: true};
  }

  // collect capability IDs and delegators for all delegated capabilities in
  // chain (skip root) so they can be checked for revocation
  const capabilities = [];
  for(const [i, capability] of capabilityChain.entries()) {
    // skip root zcap, it cannot be revoked
    if(i === 0) {
      continue;
    }
    const [{purposeResult}] = capabilityChainMeta[i].verifyResult.results;
    if(purposeResult && purposeResult.delegator) {
      capabilities.push({
        capabilityId: capability.id,
        delegator: purposeResult.delegator.id,
      });
    }
  }

  const revoked = await brZCapStorage.revocations.isRevoked({capabilities});
  if(revoked) {
    return {
      valid: false,
      error: new Error(
        'One or more capabilities in the chain have been revoked.')
    };
  }

  return {valid: true};
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
