/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const c = bedrock.util.config.main;
const cc = c.computer();
const path = require('path');
require('bedrock-validation');

const namespace = 'kms-http';
const cfg = config[namespace] = {};

const basePath = '/kms';

const kmsCfg = config['kms-http'] = {};
kmsCfg.routes = {
  basePath
};
cc('kms-http.routes.operations', () =>
  `${cfg.routes.basePath}/operations`);

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas'));
