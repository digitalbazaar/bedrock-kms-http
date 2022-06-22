/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {keystores} from '@bedrock/kms';
import {
  CapabilityAgent, KmsClient, KeystoreAgent
} from '@digitalbazaar/webkms-client';

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

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
    err.data.should.include.keys('message', 'name', 'type', 'details', 'cause');
    err.data.type.should.equal('URLMismatchError');
    err.data.details.should.have.keys(
      ['expected', 'httpStatusCode', 'actual', 'configId', 'requestUrl']);
    err.data.details.actual.should.equal(aliceKeystoreConfig.id);
    err.data.details.expected.should.equal(
      bobKeystoreAgent.keystoreId);
  });

  it('updates config and uses key proving cache busting', async () => {
    const keystoreId = aliceKeystoreConfig.id;
    const kmsClient = new KmsClient({httpsAgent});

    // create zcap agents to take over the keystore
    const agent1 = await CapabilityAgent.fromSecret(
      {secret: 'bd926f4c-38e4-4c3a-9a17-0e2608ee0a01', handle: 'primary'});
    const agent2 = await CapabilityAgent.fromSecret(
      {secret: 'd830baa9-02a6-4bd3-9072-de256b0b6c2d', handle: 'primary'});
    const agent3 = await CapabilityAgent.fromSecret(
      {secret: '37224754-647e-469a-9639-193a2833c69a', handle: 'primary'});

    const aliceKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: aliceCapabilityAgent, keystoreId, kmsClient});
    const agent1KeystoreAgent = new KeystoreAgent(
      {capabilityAgent: agent1, keystoreId, kmsClient});
    // const agent2KeystoreAgent = new KeystoreAgent(
    //   {capabilityAgent: agent2, keystoreId, kmsClient});
    const agent3KeystoreAgent = new KeystoreAgent(
      {capabilityAgent: agent3, keystoreId, kmsClient});

    // generate a key for use
    const hmacKey = await aliceKeystoreAgent.generateKey({type: 'hmac'});

    // delegate zcap for updating config from agent2 to agent3 to test
    // cache busting with delegated zcap
    const rootCapability = ZCAP_ROOT_PREFIX + encodeURIComponent(keystoreId);
    const agent3Zcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: agent3.id,
      invocationTarget: keystoreId,
      delegator: agent2
    });

    // delegate zcap for updating config from agent3 to agent2 to agent1 to
    // test cache busting with deep delegated zcap
    const agent2Zcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: agent2.id,
      invocationTarget: keystoreId,
      delegator: agent3
    });
    const agent1Zcap = await helpers.delegate({
      parentCapability: agent2Zcap,
      controller: agent1.id,
      invocationTarget: keystoreId,
      delegator: agent2
    });

    // update Alice's keystore config controller to agent1
    let config = {...aliceKeystoreConfig};

    try {
      // disable cache delete functionality on update
      keystores._disableClearCacheOnUpdate(true);

      // update controller alice => agent1 (no cache busting required)
      {
        config.sequence++;
        config.controller = agent1.id;
        const result = await aliceKeystoreAgent.updateConfig({config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent1.id);
        ({config} = result);
      }

      // update controller agent1 => agent2 (requires cache busting by
      // inspecting the root zcap)
      {
        config.sequence++;
        config.controller = agent2.id;
        const result = await agent1KeystoreAgent.updateConfig({config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent2.id);
        ({config} = result);
      }

      // update controller agent2 => agent3 (requires cache busting by
      // inspecting a delegated zcap)
      {
        config.sequence++;
        config.controller = agent3.id;
        const result = await agent3KeystoreAgent.updateConfig(
          {capability: agent3Zcap, config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent3.id);
        ({config} = result);
      }

      // update controller agent3 => agent1 (requires cache busting by
      // inspecting a deep delegated zcap)
      {
        config.sequence++;
        config.controller = agent1.id;
        const result = await agent1KeystoreAgent.updateConfig(
          {capability: agent1Zcap, config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent1.id);
        ({config} = result);
      }

      // update controller back to alice to test key op cache busting
      {
        config.sequence++;
        config.controller = aliceCapabilityAgent.id;
        const result = await agent1KeystoreAgent.updateConfig({config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(aliceCapabilityAgent.id);
        ({config} = result);
      }

      // use hmac key as alice (requires cache busting by inspecting root
      // zcap)
      await hmacKey.sign({data: new Uint8Array([0])});

      // update controller alice => agent1 (no cache busting required)
      {
        config.sequence++;
        config.controller = agent1.id;
        const result = await aliceKeystoreAgent.updateConfig({config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent1.id);
        ({config} = result);
      }

      // use hmac key as agent1 (requires cache busting by
      // inspecting the root zcap)
      hmacKey.invocationSigner = agent1.getSigner();
      // use different data each time to avoid hmac caching
      await hmacKey.sign({data: new Uint8Array([1])});

      // update controller agent1 => agent2 (requires cache busting by
      // inspecting the root zcap)
      {
        config.sequence++;
        config.controller = agent2.id;
        const result = await agent1KeystoreAgent.updateConfig({config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent2.id);
        ({config} = result);
      }

      // use hmac key as agent3 (requires cache busting by
      // inspecting a delegated zcap)
      hmacKey.capability = agent3Zcap;
      hmacKey.invocationSigner = agent3.getSigner();
      // use different data each time to avoid hmac caching
      await hmacKey.sign({data: new Uint8Array([1])});

      // update controller agent2 => agent3 (cache should already be fresh)
      {
        config.sequence++;
        config.controller = agent3.id;
        const result = await agent3KeystoreAgent.updateConfig(
          {capability: agent3Zcap, config});
        result.config.id.should.eql(config.id);
        result.config.controller.should.eql(agent3.id);
        ({config} = result);
      }

      // use hmac key as agent1 (requires cache busting by
      // inspecting a deep delegated zcap)
      hmacKey.capability = agent1Zcap;
      hmacKey.invocationSigner = agent1.getSigner();
      // use different data each time to avoid hmac caching
      await hmacKey.sign({data: new Uint8Array([1])});
    } catch(e) {
      assertNoError(e);
    } finally {
      keystores._disableClearCacheOnUpdate(false);
    }
  });
});
