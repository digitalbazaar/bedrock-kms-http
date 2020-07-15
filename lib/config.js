/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
require('bedrock-validation');
const path = require('path');

const namespace = 'kms-http';
const cfg = config[namespace] = {};

const basePath = '/kms';
cfg.routes = {
  basePath
};

// optionally require an authenticated session
// this option may be set to false when operating behind an authenticated proxy
cfg.requireAuthentication = true;

config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);
