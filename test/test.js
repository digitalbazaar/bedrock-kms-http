/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
require('bedrock-https-agent');
require('bedrock-kms-http');
require('bedrock-ssm-mongodb');

require('bedrock-test');
bedrock.start();
