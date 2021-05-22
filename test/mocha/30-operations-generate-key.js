/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const helpers = require('./helpers');

const KMS_MODULE = 'ssm-v1';

describe('generateKey with ipAllowList', () => {
  it('generates a key', async () => {
    // source of requests in the test suite are from 127.0.0.1
    const secret = '22612679-05ce-4ffd-bf58-22b3c4bc1314';
    const handle = 'testKeyAllowList';
    const ipAllowList = ['127.0.0.1/32'];
    const keystoreAgent = await helpers.createKeystoreAgent(
      {handle, ipAllowList, secret, keyType: 'Ed25519VerificationKey2020'});
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
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
      }, keyType: 'Ed25519VerificationKey2020'
    });
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
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
      {handle, ipAllowList, secret, keyType: 'Ed25519VerificationKey2020'});
    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
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
      {handle, ipAllowList, secret, keyType: 'Ed25519VerificationKey2020'});

    let err;
    let result;
    try {
      result = await keystoreAgent.generateKey({
        kmsModule: KMS_MODULE,
        type: 'hmac',
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
  });
}); // generateKey with ipAllowList
