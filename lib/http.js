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
      const result = await brKms.runOperation({operation});
      res.json(result);
    }));
});
