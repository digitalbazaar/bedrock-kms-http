/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');
require('bedrock-kms-http');

config.mocha.tests.push(path.join(__dirname, 'mocha'));
