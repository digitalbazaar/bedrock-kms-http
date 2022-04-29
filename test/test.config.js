/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import '@bedrock/https-agent';
import '@bedrock/kms-http';
import '@bedrock/mongodb';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// MongoDB
config.mongodb.name = 'bedrock_kms_http_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

// do not require an authentication session for tests
config['kms-http'].requireAuthentication = false;

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
