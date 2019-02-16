/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const asyncHandler = require('express-async-handler');
const bedrock = require('bedrock');
//const brPassport = require('bedrock-passport');
const {config} = bedrock;
const {validate} = require('bedrock-validation');
require('bedrock-express');
/*const {
  ensureAuthenticated
} = brPassport;
const {BedrockError} = bedrock.util;*/

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
    // TODO: figure out authentication
    /*ensureAuthenticated,*/
    validate('kms-http.postOperation'),
    asyncHandler(async (req, res) => {
      // TODO: find matching plugin via bedrock-kms and pass operation and
      // parameters
      res.status(200).end();
    }));
});
