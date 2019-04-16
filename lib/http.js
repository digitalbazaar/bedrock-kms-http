/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brKms = require('bedrock-kms');
const {config, util: {BedrockError}} = bedrock;
const {createMiddleware} = require('bedrock-passport');
const {validate} = require('bedrock-validation');
const URL = require('url');

// load config defaults
require('./config');

// module API
const api = {};
module.exports = api;

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];
  const {routes} = cfg;

  // execute a KMS operation
  app.post(
    routes.operations,
    createMiddleware({strategy: 'session'}),
    validate('kms-http.postOperation'),
    asyncHandler(async (req, res) => {
      // optionally require an authenticated session
      // there are no specific permissions required, any authenticated account
      // may perform KMS operations
      if(cfg.requireAuthentication && !req.user) {
        throw new BedrockError('Permission denied.', 'NotAllowedError', {
          httpStatusCode: 400,
          public: true,
        });
      }
      const operation = req.body;

      // ensure that the last two elements in the URL match the invocationTarget
      // the full URL is not checked here in support of proxied operation
      // where the local KMS hostname may differ from the public host.
      let targetUrl;
      if(typeof operation.invocationTarget === 'string') {
        targetUrl = operation.invocationTarget;
      } else {
        targetUrl = URL.parse(operation.invocationTarget.id).path;
      }
      const targetFragment = targetUrl.split('/').slice(-2);
      const pathFragment = req.originalUrl.split('/').slice(-2);
      const valid = targetFragment.every((e, i) => pathFragment[i] === e);

      if(!valid) {
        throw new BedrockError('invocationTarget.id mismatch.', 'SyntaxError', {
          httpStatusCode: 400,
          public: true,
        });
      }

      const result = await brKms.runOperation({operation});
      res.json(result);
    }));
});
