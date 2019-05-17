/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const base58 = require('bs58');
const {runOperation, validateOperation} = require('bedrock-kms');
const {config, util: {BedrockError}} = bedrock;
const {createMiddleware} = require('bedrock-passport');
const URL = require('url');

// load config defaults
require('./config');

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];
  const {routes} = cfg;

  // execute a KMS operation
  app.post(
    routes.operations,
    createMiddleware({strategy: 'session'}),
    asyncHandler(async (req, res) => {
      await validateOperation({operation: req.body});

      // optionally require an authenticated session for a GenerateKeyOperation
      // there are no specific permissions required, any authenticated account
      // may perform the operation
      const {type} = req.body;
      if(cfg.requireAuthentication && type === 'GenerateKeyOperation' &&
        !req.user) {
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 400,
          public: true,
        });
      }
      const operation = req.body;

      // TODO: validate that `keyId` is a UUID
      const {keyId} = req.params;

      // TODO: ensure that invocationTarget matches expected full request url
      // taking into consideration different public host

      // FIXME: we should be checking the full URL but currently:
      // ensure that the path in the URL matches the invocationTarget;
      // the full URL is not checked here in support of proxied operation
      // where the local KMS hostname may differ from the public host
      let targetUrl;
      if(typeof operation.invocationTarget === 'string') {
        targetUrl = operation.invocationTarget;
      } else {
        targetUrl = operation.invocationTarget.id;
      }
      targetUrl = URL.parse(targetUrl).path;
      const valid = targetUrl === req.originalUrl;

      if(!valid) {
        throw new BedrockError('invocationTarget.id mismatch.', 'SyntaxError', {
          httpStatusCode: 400,
          public: true,
        });
      }

      const result = await runOperation({operation, documentLoader});
      res.json(result);
    }));
});

async function documentLoader(url) {
  // TODO: move to did-key lib
  if(url.startsWith('did:key:')) {
    const publicKeyBase58 = _parsePublicKeyBase58(url);
    return {
      contextUrl: null,
      documentUrl: url,
      document: {
        '@context': 'https://w3id.org/security/v2',
        id: url,
        publicKey: [{
          id: url,
          // TODO: determine from parsing multibase key
          type: 'Ed25519VerificationKey2018',
          controller: url,
          publicKeyBase58
        }],
        authentication: [url],
        assertionMethod: [url],
        capabilityDelegation: [url],
        capabilityInvocation: [url]
      }
    };
  }
  const error = new Error(`Dereferencing url "${url}" is prohibited.`);
  error.name = 'NotAllowedError';
  error.httpStatusCode = 400;
  throw error;
}

function _parsePublicKeyBase58(didKeyUrl) {
  const fingerprint = didKeyUrl.substr('did:key:'.length);
  // skip leading `z` that indicates base58 encoding
  const buffer = base58.decode(fingerprint.substr(1));
  // assume buffer is: 0xed 0x01 <public key bytes>
  return base58.encode(buffer.slice(2));
}
