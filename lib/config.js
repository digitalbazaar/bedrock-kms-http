/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const c = bedrock.util.config.main;
const cc = c.computer();
require('bedrock-validation');

const namespace = 'kms-http';
const cfg = config[namespace] = {};

const basePath = '/kms';
cfg.routes = {
  basePath
};
cc('kms-http.routes.operations', () => `${cfg.routes.basePath}/:uuid`);

// optionally require an authenticated session
// this option may be set to false when operating behind an authenticated proxy
cfg.requireAuthentication = true;
