/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {util: {uuid}} = require('bedrock');
const pMap = require('p-map');

const helpers = require('./helpers');

const KMS_MODULE = 'ssm-v1';

describe('bedrock-kms-http HMAC operations', () => {
  describe('Sha256HmacKey2019', () => {
    let hmac;
    before(async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';
      const keystoreAgent = await helpers.createKeystoreAgent({handle, secret});
      hmac = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
    });
    it('successfully signs', async () => {
      const data = new TextEncoder('utf-8').encode('hello');
      let err;
      let result;
      try {
        result = await hmac.sign({data});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.a('string');
    });

    describe('bulk operations', () => {
      const operationCount = 10000;
      const vData = [];
      before(async () => {
        for(let i = 0; i < operationCount; ++i) {
          let v = '';
          for(let n = 0; n < 100; ++n) {
            v += uuid();
          }
          vData.push(new TextEncoder('utf-8').encode(v));
        }
      });
      it(`performs ${operationCount} signatures`, async function() {
        this.timeout(0);
        let result;
        let err;
        try {
          result = await pMap(
            vData, data => hmac.sign({data}), {concurrency: 10});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.an('array');
        result.should.have.length(operationCount);
      });
    }); // end bulk operations
  }); // end Sha256HmacKey2019

  describe('Sha256HmacKey2019 with ipAllowList', () => {
    it('successfully signs', async () => {
      const secret = ' 22612679-05ce-4ffd-bf58-22b3c4bc1314';
      const handle = 'testKeyAllowList';
      const ipAllowList = ['127.0.0.1/32'];
      const keystoreAgent = await helpers.createKeystoreAgent(
        {handle, ipAllowList, secret});
      const hmac = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
      const data = new TextEncoder('utf-8').encode('hello');
      let err;
      let result;
      try {
        result = await hmac.sign({data});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.a('string');
    });
  }); // end Sha256HmacKey2019 with ipAllowList
});
