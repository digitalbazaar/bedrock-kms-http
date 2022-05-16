/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brZCapStorage from '@bedrock/zcap-storage';
import * as helpers from './helpers.js';
import {asyncHandler} from '@bedrock/express';
import {BedrockKeystoreConfigStorage} from './BedrockKeystoreConfigStorage.js';
import {createRequire} from 'node:module';
import {
  defaultDocumentLoader as documentLoader,
  defaultModuleManager as moduleManager
} from '@bedrock/kms';
import {logger} from './logger.js';
import {reportOperationUsage} from './metering.js';
const require = createRequire(import.meta.url);
const {
  authorizeZcapInvocation: _authorizeZcapInvocation,
  authorizeZcapRevocation: _authorizeZcapRevocation
} = require('@digitalbazaar/ezcap-express');
const {createOperationMiddleware} = require('@digitalbazaar/webkms-switch');
const {CryptoLD} = require('crypto-ld');
const {Ed25519Signature2020} =
  require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');

const {config, util: {BedrockError}} = bedrock;

const FIVE_MINUTES = 1000 * 60 * 5;

const storage = new BedrockKeystoreConfigStorage();

// create `getVerifier` hook for verifying zcap invocation HTTP signatures
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

// creates middleware to get the keystore config for the current request and
// caches it in `req.webkms.keystore`
export function createGetKeystoreConfig({routes}) {
  return asyncHandler(async function _getKeystoreConfig(req, res, next) {
    if(!req.webkms) {
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const configRecord = await storage.get({
        id: keystoreId, req, returnRecord: true
      });
      const {config: keystore} = configRecord;
      req.webkms = {keystore, configRecord};
    }
    next();
  });
}

// creates middleware for handling KMS operations
export function createKmsOperationMiddleware() {
  const {kmsOperationOptions} = config['kms-http'];
  return createOperationMiddleware({
    ...kmsOperationOptions,
    storage, moduleManager, documentLoader,
    expectedHost: config.server.host, getVerifier,
    inspectCapabilityChain,
    onError, onSuccess: reportOperationUsage, suiteFactory
  });
}

// calls ezcap-express's authorizeZcapInvocation w/constant params, exposing
// only those params that change in this module
export function authorizeZcapInvocation({
  getExpectedValues, getRootController
}) {
  return _authorizeZcapInvocation({
    documentLoader, getExpectedValues, getRootController,
    getVerifier,
    inspectCapabilityChain,
    onError,
    suiteFactory
  });
}

// creates middleware for keystore route authz checks
export function authorizeKeystoreZcapInvocation() {
  return authorizeZcapInvocation({
    async getExpectedValues({req}) {
      return {
        host: config.server.host,
        rootInvocationTarget: req.webkms.keystore.id
      };
    },
    getRootController: getKeystoreController,
  });
}

// creates middleware for revocation of zcaps for keystores
export function authorizeZcapRevocation() {
  return _authorizeZcapRevocation({
    documentLoader,
    expectedHost: config.server.host,
    getRootController: getKeystoreController,
    getVerifier,
    inspectCapabilityChain,
    onError,
    suiteFactory
  });
}

async function getKeystoreController({req}) {
  /* The following code is to prevent false-negative authz errors that are the
  result of stale cached keystore configs.

  It is a common pattern for keystore configs to have their root controllers
  updated immediately after creation based on the value of a key that is in the
  keystore itself. When this happens, decentralized caches may hold a stale
  config with the old controller value. A client that uses a zcap that is
  delegated / controlled by the root controller would see a false negative
  authz error if the authz check used the cached value.

  Therefore, this code will check whether keystore configs are reasonably new
  and whether a failure is likely to occur on account of a mismatched root
  controller. If this seems likely, a fresh copy of the keystore config record
  is retrieved.

  Algorithm: If the keystore config is less than five minutes old, then inspect
  `req.ezcap.invocationParameters.capability` or `req.ezcap.capabilityToRevoke`
  to ensure that:

  1. The `capability` is the root zcap and the ID or the controller of the
    invoking verification method matches the keystore controller (note: can't
    revoke a root zcap so this is an invoke-only case).
  2. The `capability` (being invoked or revoked) is delegated and the
    ID or controller of the delegating verification method for the first
    delegated zcap in the chain matches the keystore controller.

  If neither condition is true, fetch a fresh version of the keystore config
  record and update `req.webkms`. */
  const now = Date.now();
  if((now - req.webkms.configRecord.meta.created) > FIVE_MINUTES ||
    (req.ezcap.capabilityToRevoke && req.ezcap.invocationParameters)) {
    // config is either older than five minutes or we've already been through
    // this code path for the current request to run the checks against a
    // zcap that is to be revoked (in which case we must not update again to
    // ensure the keystore config used is consistent)
    return req.webkms.keystore.controller;
  }

  // check for a zcap from the invocation params or for one to be revoked; the
  // same rules above will be used to check if we need a fresh config record
  const capability = req.ezcap?.invocationParameters?.capability ||
    req.ezcap.capabilityToRevoke;

  // capability is root if it is a string; and it must be invoked because you
  // can't revoke a root zcap
  const isRoot = typeof capability === 'string';
  let keyId;
  if(isRoot && req.ezcap.invocationParameters) {
    // get verification method (key) ID from invocation params
    ({signature: {params: {keyId}}} = req.ezcap);
  } else {
    // get verification method (key) ID from first delegation proof
    if(capability?.proof?.capabilityChain.length === 1) {
      // capability *is* the delegated zcap
      keyId = capability.proof?.verificationMethod;
    } else {
      // capability is delegated further down the chain
      keyId = capability?.proof?.capabilityChain[1]?.proof?.verificationMethod;
    }
  }

  if(!keyId) {
    logger.debug(
      'No verification method found in zcap when trying to bust keystore ' +
      'config cache.');

    // no verification method to check, use cached keystore controller
    return req.webkms.keystore.controller;
  }

  // fetch verification method early to compare against keystore controller
  const {verificationMethod} = await getVerifier({keyId, documentLoader});

  // get fresh record if VM ID nor controller matches keystore controller
  if(!(verificationMethod.controller === req.webkms.keystore.controller ||
    verificationMethod.id === req.webkms.keystore.controller)) {
    const configRecord = await storage.get({
      id: req.webkms.keystore.id, req, returnRecord: true, fresh: true
    });
    const {config: keystore} = configRecord;
    req.webkms = {keystore, configRecord};
    logger.debug('Forced fresh keystore config retrieval during zcap check.');
  }

  return req.webkms.keystore.controller;
}

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
  if(!(error instanceof BedrockError)) {
    // always expose cause message and name; expose cause details as
    // BedrockError if error is marked public
    let details = {};
    if(error.details && error.details.public) {
      details = error.details;
    }
    error = new BedrockError(
      error.message,
      error.name || 'NotAllowedError', {
        ...details,
        public: true,
      }, error);
  }
  throw new BedrockError(
    'Authorization error.', 'NotAllowedError', {
      httpStatusCode: 403,
      public: true,
    }, error);
}

// hook used to create suites for verifying zcap delegation chains
async function suiteFactory() {
  return new Ed25519Signature2020();
}
