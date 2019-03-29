/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brKms = require('bedrock-kms');
const {config} = bedrock;
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
    validate('kms-http.postOperation'),
    asyncHandler(async (req, res) => {
      // get key ID, plugin, and operation from request
      const keyId = req.url;
      const {plugin} = req.params;
      const operation = req.body;

      const result = await brKms.runOperation({keyId, plugin, operation});

      res.json(result);
    }));
});
