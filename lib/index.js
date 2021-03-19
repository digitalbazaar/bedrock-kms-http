/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-express');
require('bedrock-namespace');

require('./http-namespace');
require('./http');
require('./http-revocations');

// load config defaults
require('./config');
