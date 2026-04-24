/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import * as process from 'node:process';
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

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// test kms module proxy
if(process.env.TEST_PROXY) {
  config['kms-http'].kmsModuleProxy = {
    'ssm-v1': {
      // https
      proxyTarget: 'https://localhost:22144'
      // http
      //proxyTarget: 'http://localhost:22180'
    }
  };
}

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
