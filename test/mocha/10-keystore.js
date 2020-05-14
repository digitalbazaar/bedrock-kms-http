/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {CapabilityAgent} = require('webkms-client');
const helpers = require('./helpers');

describe('bedrock-kms-http API', () => {
  describe('keystores', () => {
    it('creates a keystore', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      let err;
      let result;
      try {
        result = await helpers.createKeystore({capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);
    });
    it('throws error on receivedHost not equal to allowedHost', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';
      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});
      let err;
      let result;

      // intentionally specifying a host name other than a local host
      const kmsBaseUrl = 'https://127.0.0.1:18443/kms';

      try {
        result = await helpers.createKeystore({capabilityAgent, kmsBaseUrl});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.response.data.message.should.contain(
        'Permission denied. Expected host'
      );
    });
  });
});
