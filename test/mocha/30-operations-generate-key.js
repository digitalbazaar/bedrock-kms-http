/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brHttpsAgent = require('bedrock-https-agent');
const {CapabilityAgent, KmsClient, KeystoreAgent} =
  require('@digitalbazaar/webkms-client');
const {httpClient, DEFAULT_HEADERS} = require('@digitalbazaar/http-client');
const {signCapabilityInvocation} = require('http-signature-zcap-invoke');
const {agent} = require('bedrock-https-agent');
const helpers = require('./helpers');

describe('generateKey with ipAllowList', () => {
  it('generates a key', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = '22612679-05ce-4ffd-bf58-22b3c4bc1314';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['127.0.0.1/32'];
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
    result.should.have.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient',
      'cache', '_pruneCacheTimer'
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
    result.should.have.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient',
      'cache', '_pruneCacheTimer'
    ]);
  });
  it('generates a key with multiple ipAllowList entries', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = 'efef2772-f7aa-4d25-9eac-6228f2a64b3b';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['8.8.8.8/32', '127.0.0.1/32'];
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
    result.should.have.keys([
      'algorithm', 'capability', 'id', 'type', 'invocationSigner', 'kmsClient',
      'cache', '_pruneCacheTimer'
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
}); // generateKey with ipAllowList∏∏

describe('get public key description', () => {
  it('gets public key description', async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bobKey';
    const capabilityAgent = await CapabilityAgent.fromSecret(
      {secret, handle});
    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent});
    const {httpsAgent} = brHttpsAgent;
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
      result = await httpClient.get(url, {agent, headers});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.data.should.have.keys([
      '@context', 'id', 'type', 'publicKeyMultibase'
    ]);
    result.data.id.should.equal(key.id);
    result.data.type.should.equal(key.type);
  });
});
