/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brKms = require('bedrock-kms');
//const brPassport = require('bedrock-passport');
const {config} = bedrock;
// TODO: remove once handled by bedrock-passport?
const {parseRequest} = require('http-signature-header');
const {validate} = require('bedrock-validation');
/*const {
  ensureAuthenticated
} = brPassport;*/
const {BedrockError} = bedrock.util;

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
      // TODO: use `req.user` instead
      // get `controller` from key ID in Authorization header
      const parsed = parseRequest(
        req, {headers: ['expires', 'host', '(request-target)']});
      const controller = parsed.keyId;

      // TODO: it is not clear how the `plugin` will be specified, will it
      // be via a URL param, encoded somehow in an ID, leaving it this way
      // for now.

      // parse operation from POST data
      const {method, parameters = {}, plugin} = req.body;
      // TODO: validate method, parameters, plugin

      // FIXME: this could/should be made an enum in the json schema validator
      // what are all the supported methods?  Seems like the model should be
      // that we allow a list of supported methods here, and bedrock-kms,
      // the plugin wrapper, will throw if a plugin does not implement that
      // method, or something along these lines.

      // prevent calling private methods
      if(typeof method !== 'string' || method.startsWith('_')) {
        throw new BedrockError(
          `Method "${method}" is not allowed.`,
          'NotAllowedError', {public: true, httpStatusCode: 400});
      }

      const result = await brKms.callMethod(
        {controller, method, parameters, plugin});

      res.json(result);
    }));
});
