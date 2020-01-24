/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');
require('bedrock-kms-http');

// do not require an authentication session for tests
config['kms-http'].requireAuthentication = false;

config.mocha.tests.push(path.join(__dirname, 'mocha'));

config.kms.allowedHost = config.server.host;
