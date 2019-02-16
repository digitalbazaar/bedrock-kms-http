/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const https = require('https');
// allow self-signed cert for tests
const axios = require('axios').create({
  httpsAgent: new https.Agent({
    rejectUnauthorized: false
  })
});
const {config} = require('bedrock');
//const helpers = require('./helpers');

describe('bedrock-kms-http API', () => {
  describe('operations', () => {
    it('should execute a "generateKey" operation', async () => {
      let err;
      try {
        //await axios.post(...);
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.exist(err.response);
      err.response.status.should.equal(400);
    });
    it('should fail to execute a "generateKey" operation', async () => {
    });
  });
});
