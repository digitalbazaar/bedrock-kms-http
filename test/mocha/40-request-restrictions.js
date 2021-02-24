/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent, KeystoreAgent, KmsClient} = require('webkms-client');
const helpers = require('./helpers');
// TextEncoder is not a global in node 10
const {TextEncoder} = require('util');
const brHttpsAgent = require('bedrock-https-agent');

const KMS_MODULE = 'ssm-v1';

describe('bedrock-kms-http', () => {
  describe('operation restrictions', () => {
    let hmac;
    before(async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      let err;
      let keystore;
      try {
        keystore = await helpers.createKeystore({capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);

      // create kmsClient only required because we need to use httpsAgent
      // that accepts self-signed certs used in test suite
      const {httpsAgent} = brHttpsAgent;
      const kmsClient = new KmsClient({httpsAgent});
      const keystoreAgent = new KeystoreAgent({
        capabilityAgent,
        keystore,
        kmsClient
      });
      hmac = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
    });
    afterEach(() => {
      bedrock.config.kms.allowedHost = 'localhost:18443';
    });
    it('should allow an operation from an allowedHost', async () => {
      const data = new TextEncoder('utf-8').encode('hello');
      let err;
      let result;
      try {
        result = await hmac.sign({data});
      } catch(e) {
        err = err;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.a('string');
    });
    it('should not allow an operation from an unknown Host', async () => {
      bedrock.config.kms.allowedHost = 'production.com';
      const data = new TextEncoder('utf-8').encode('hello');
      let err;
      let result;
      try {
        result = await hmac.sign({data});
      } catch(e) {
        err = err;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.a('string');
    });
    it('should not allow an operation from an allowedHost with an unknown ip',
      async () => {
        const data = new TextEncoder('utf-8').encode('hello');
        let err;
        let result;
        try {
          result = await hmac.sign({data});
        } catch(e) {
          err = err;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.a('string');
      });
    it('should allow an operation from an allowedHost with a known ip',
      async () => {
        const data = new TextEncoder('utf-8').encode('hello');
        let err;
        let result;
        try {
          result = await hmac.sign({data});
        } catch(e) {
          err = err;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.a('string');
      });
  });
});
