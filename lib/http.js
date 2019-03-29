/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brKms = require('bedrock-kms');
const {config} = bedrock;
const URL = require('url');
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
      const operation = req.body;
      const result = await brKms.runOperation({operation});
      res.json(result);
    }));
});
