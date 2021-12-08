/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');
require('bedrock-express');

// MongoDB
config.mongodb.name = 'bedrock_kms_http_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

// do not require an authentication session for tests
config['kms-http'].requireAuthentication = false;

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// configure karma tests
config.karma.suites['bedrock-web-kms'] = path.join('web', '**', '*.js');
config.karma.config.proxies = {
  '/': {
    target: 'https://localhost:18443',
    changeOrigin: true
  }
};
config.karma.config.proxyValidateSSL = false;
config.karma.config.browserNoActivityTimeout = 120000;
config.karma.config.browserDisconnectTimeout = 120000;

config['https-agent'].keepAlive = true;
