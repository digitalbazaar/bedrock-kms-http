/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {
  CapabilityAgent, KeystoreAgent, KmsClient
} from '@digitalbazaar/webkms-client';
import {DEFAULT_HEADERS, httpClient} from '@digitalbazaar/http-client';
import {httpsAgent} from '@bedrock/https-agent';
import {
  signCapabilityInvocation
} from '@digitalbazaar/http-signature-zcap-invoke';

describe('generateKey', () => {
  it('generates a key', async () => {
    const secret = '0628a44e-7599-11ec-989d-10bf48838a41';
    const handle = 'testKey';
    const keystoreAgent = await helpers.createKeystoreAgent(
      {handle, secret});
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({type: 'hmac'});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.include.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient'
    ]);
  });
  it('generates a key with ipAllowList', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = '22612679-05ce-4ffd-bf58-22b3c4bc1314';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['127.0.0.1/32', '::1/128'];
    const keystoreAgent = await helpers.createKeystoreAgent(
      {handle, ipAllowList, secret});
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({type: 'hmac'});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.include.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient'
    ]);
  });
  it('generates a key with x-forwarded-for header', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = '22612679-05ce-4ffd-bf58-22b3c4bc1314';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['8.8.8.8/32'];
    const keystoreAgent = await helpers.createKeystoreAgent({
      handle, ipAllowList, secret, kmsClientHeaders: {
        'x-forwarded-for': '8.8.8.8',
      }
    });
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({type: 'hmac'});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.include.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient'
    ]);
  });
  it('generates a key with multiple ipAllowList entries', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = 'efef2772-f7aa-4d25-9eac-6228f2a64b3b';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['8.8.8.8/32', '127.0.0.1/32', '::1/128'];
    const keystoreAgent = await helpers.createKeystoreAgent(
      {handle, ipAllowList, secret});
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({type: 'hmac'});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.include.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient'
    ]);
  });
  it('returns NotAllowedError for invalid source IP', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = '860a6bc8-74e1-4dfd-b701-7efc2a596e91';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['8.8.8.8/32'];
    const keystoreAgent = await helpers.createKeystoreAgent(
      {handle, ipAllowList, secret});

    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({type: 'hmac'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
  });
  it('generates a key with "maxCapabilityChainLength=1"', async () => {
    const secret = '0ad59134-7583-11ec-b16e-10bf48838a41';
    const handle = 'testKeyMaxCapabilityChainLength';
    const keystoreAgent = await helpers.createKeystoreAgent(
      {handle, secret});
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({
        type: 'asymmetric', maxCapabilityChainLength: 1
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.include.keys([
      'capability', 'id', 'type', 'invocationSigner', 'kmsClient', 'kmsId'
    ]);
  });
}); // generateKey with ipAllowList

describe('get public key description', () => {
  it('gets public key description', async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bobKey';
    const capabilityAgent = await CapabilityAgent.fromSecret(
      {secret, handle});
    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent});
    const kmsClient = new KmsClient({keystoreId, httpsAgent});
    let keystoreAgent;
    try {
      keystoreAgent = new KeystoreAgent(
        {capabilityAgent, keystoreId, kmsClient});
    } catch(e) {
      assertNoError(e);
    }
    const key = await keystoreAgent.generateKey({type: 'asymmetric'});

    const url = key.id;
    const headers = await signCapabilityInvocation({
      url, method: 'get',
      headers: DEFAULT_HEADERS,
      capability: 'urn:zcap:root:' + encodeURIComponent(url),
      invocationSigner: capabilityAgent.getSigner(),
      capabilityAction: 'read'
    });

    let err;
    let result;
    try {
      result = await httpClient.get(url, {agent: httpsAgent, headers});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.data.should.include.keys([
      '@context', 'id', 'type', 'publicKeyMultibase', 'controller'
    ]);
    result.data.id.should.equal(key.id);
    result.data.type.should.equal(key.type);
  });
});
