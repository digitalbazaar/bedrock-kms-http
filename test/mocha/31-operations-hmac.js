/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import pMap from 'p-map';
const require = createRequire(import.meta.url);
const {CapabilityAgent, Hmac, KmsClient} = require(
  '@digitalbazaar/webkms-client');

const {util: {uuid}} = bedrock;

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

describe('bedrock-kms-http HMAC operations', () => {
  describe('Sha256HmacKey2019', () => {
    let hmac;
    before(async () => {
      const secret = 'b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';
      const keystoreAgent = await helpers.createKeystoreAgent({handle, secret});
      hmac = await keystoreAgent.generateKey({type: 'hmac'});
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
      result.should.be.a('Uint8Array');
    });
  }); // end Sha256HmacKey2019

  describe('Sha256HmacKey2019 with ipAllowList', () => {
    it('successfully signs', async () => {
      const secret = '22612679-05ce-4ffd-bf58-22b3c4bc1314';
      const handle = 'testKeyAllowList';
      const ipAllowList = ['127.0.0.1/32'];
      const keystoreAgent = await helpers.createKeystoreAgent(
        {handle, ipAllowList, secret});
      const hmac = await keystoreAgent.generateKey({type: 'hmac'});
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
      result.should.be.a('Uint8Array');
    });
    it('fails when "maxCapabilityChainLength" is exceeded', async () => {
      const secret = '22612679-05ce-4ffd-bf58-22b3c4bc1314';
      const handle = 'testKeyMaxCapabilityChainLength';
      const keystoreAgent = await helpers.createKeystoreAgent(
        {handle, secret});
      const hmac = await keystoreAgent.generateKey({
        type: 'hmac', maxCapabilityChainLength: 1
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
      result.should.be.a('Uint8Array');

      // now delegate and try to invoke
      const delegatee = await CapabilityAgent.fromSecret({
        secret: uuid(),
        handle: uuid()
      });
      const rootCapability = ZCAP_ROOT_PREFIX +
        encodeURIComponent(keystoreAgent.keystoreId);
      const delegatedZcap = await helpers.delegate({
        parentCapability: rootCapability,
        controller: delegatee.id,
        invocationTarget: hmac.id,
        allowedAction: 'sign',
        delegator: keystoreAgent.capabilityAgent
      });
      const hmac2 = await Hmac.fromCapability({
        capability: delegatedZcap,
        invocationSigner: delegatee.getSigner(),
        kmsClient: new KmsClient({httpsAgent})
      });

      let err2;
      let result2;
      try {
        result2 = await hmac2.sign({data});
      } catch(e) {
        err2 = e;
      }
      should.exist(err2);
      should.not.exist(result2);
      should.exist(err2.data);
      err2.data.type.should.equal('NotAllowedError');
      should.exist(err2.data.cause);
      err2.data.cause.message.should.equal(
        'Maximum zcap invocation capability chain length (1) exceeded.');
    });
    it('successfully signs with x-forwarded-for header', async () => {
      const secret = '2726f62d-31bb-4688-b54a-1a0b4e50329f';
      const handle = 'testKeyAllowList';
      const ipAllowList = ['8.8.8.8/32'];
      const keystoreAgent = await helpers.createKeystoreAgent({
        handle, ipAllowList, secret, kmsClientHeaders: {
          'x-forwarded-for': '8.8.8.8',
        }
      });
      const hmac = await keystoreAgent.generateKey({type: 'hmac'});
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
      result.should.be.a('Uint8Array');
    });
  }); // end Sha256HmacKey2019 with ipAllowList

  describe('bulk operations', () => {
    const operationCount = 1000;
    const vData = [];
    let hmac;

    before(async () => {
      const secret = '9b5a0a63-aac2-447c-a60a-8cc79b46418d';
      const handle = 'testKeyBulk';
      const keystoreAgent = await helpers.createKeystoreAgent({handle, secret});
      hmac = await keystoreAgent.generateKey({type: 'hmac'});
    });
    before(async () => {
      for(let i = 0; i < operationCount; ++i) {
        // uuids are 37 chars long, * 30 is ~1KiB
        let v = '';
        for(let n = 0; n < 30; ++n) {
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
          vData, data => hmac.sign({data}), {concurrency: 30});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.an('array');
      result.should.have.length(operationCount);
    });
  }); // end bulk operations
});
