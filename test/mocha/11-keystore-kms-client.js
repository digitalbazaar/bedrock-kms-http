/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brHttpsAgent = require('bedrock-https-agent');
const helpers = require('./helpers');
const {CapabilityAgent, KmsClient, KeystoreAgent} = require('webkms-client');

describe('keystore API interactions using webkms-client', () => {
  let aliceCapabilityAgent;
  let aliceKeystoreConfig;
  let aliceKeystoreAgent;
  let bobCapabilityAgent;
  let bobKeystoreAgent;

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'testKey2';
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    aliceKeystoreConfig = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent});
    const {httpsAgent} = brHttpsAgent;
    const kmsClient = new KmsClient({httpsAgent});

    // eslint-disable-next-line no-unused-vars
    aliceKeystoreAgent = new KeystoreAgent({
      capabilityAgent: aliceCapabilityAgent,
      keystore: aliceKeystoreConfig,
      kmsClient,
    });
  });

  // generate a keystore for Bob
  before(async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bobKey';
    bobCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
    const keystore = await helpers.createKeystore(
      {capabilityAgent: bobCapabilityAgent});
    try {
      const {httpsAgent} = brHttpsAgent;
      const kmsClient = new KmsClient({httpsAgent});
      bobKeystoreAgent = new KeystoreAgent(
        {capabilityAgent: bobCapabilityAgent, keystore, kmsClient});
    } catch(e) {
      assertNoError(e);
    }
  });

  it('returns DataError on attempt to update and invalid config', async () => {
    // update Alice's keystore config to include ipAllowList
    aliceKeystoreConfig.sequence++;
    aliceKeystoreConfig.ipAllowList = ['8.8.8.8/32'];

    let err;
    let result;
    try {
      result = await bobKeystoreAgent.updateConfig(
        {config: aliceKeystoreConfig});
    } catch(e) {
      err = e;
    }
    should.not.exist(result);
    should.exist(err);
    err.status.should.equal(400);
    err.data.message.should.equal('Configuration "id" does not match.');
    err.data.type.should.equal('DataError');
    err.data.details.should.have.keys('httpStatusCode', 'expected', 'actual');
    err.data.details.actual.should.equal(aliceKeystoreConfig.id);
    err.data.details.expected.should.equal(bobKeystoreAgent.keystore.id);
  });
});
