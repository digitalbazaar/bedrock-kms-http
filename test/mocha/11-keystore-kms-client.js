/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const {CapabilityAgent, KmsClient, KeystoreAgent} =
  require('@digitalbazaar/webkms-client');

describe('keystore API interactions using webkms-client', () => {
  let aliceCapabilityAgent;
  let aliceKeystoreConfig;
  let bobCapabilityAgent;
  let bobKeystoreAgent;

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'alice';
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    aliceKeystoreConfig = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent});
  });

  // generate a keystore for Bob
  before(async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bob';
    bobCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent: bobCapabilityAgent});
    try {
      const kmsClient = new KmsClient({httpsAgent});
      bobKeystoreAgent = new KeystoreAgent(
        {capabilityAgent: bobCapabilityAgent, keystoreId, kmsClient});
    } catch(e) {
      assertNoError(e);
    }
  });

  it('returns error on attempt to update an invalid config', async () => {
    // update Alice's keystore config to include ipAllowList
    const config = {...aliceKeystoreConfig};
    config.sequence++;
    config.ipAllowList = ['8.8.8.8/32'];

    let err;
    let result;
    try {
      result = await bobKeystoreAgent.updateConfig({config});
    } catch(e) {
      err = e;
    }
    should.not.exist(result);
    should.exist(err);
    err.status.should.equal(400);
    err.data.should.have.keys('message', 'type', 'details', 'cause');
    err.data.type.should.equal('URLMismatchError');
    err.data.details.should.have.keys(
      ['expected', 'httpStatusCode', 'actual', 'configId', 'requestUrl']);
    err.data.details.actual.should.equal(aliceKeystoreConfig.id);
    err.data.details.expected.should.equal(
      bobKeystoreAgent.keystoreId);
  });
});
