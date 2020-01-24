/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');
require('bedrock-kms-http');

// do not require an authentication session for tests
config['kms-http'].requireAuthentication = false;

config.mocha.tests.push(path.join(__dirname, 'mocha'));

config.kms.allowedHost = config.server.host;

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;
