/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
require('bedrock-validation');
require('bedrock-app-key');
require('bedrock-meter-usage-reporter');

const namespace = 'kms-http';
const cfg = config[namespace] = {};

const basePath = '/kms';
cfg.routes = {
  basePath
};

// storage size to report to meter service
cfg.storageCost = {
  revocation: 1
};

// create dev application key for webkms (must be overridden in deployments)
// ...and `ensureConfigOverride` has already been set via
// `bedrock-app-key` so it doesn't have to be set here
config['app-key'].seeds.services.webkms = {
  id: 'did:key:z6MkwZ7AXrDpuVi5duY2qvVSx1tBkGmVnmRjDvvwzoVnAzC4',
  seedBase58: 'WXKvAtpN67uw2T5r35PQpdy9DKgzFyoU5GsgWzS96qT',
  serviceType: 'webkms'
};
