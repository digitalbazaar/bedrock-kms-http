/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent} = require('webkms-client');
const helpers = require('./helpers');
const {agent} = require('bedrock-https-agent');
const {httpClient, DEFAULT_HEADERS} = require('@digitalbazaar/http-client');
const mockData = require('./mock.data');
const {signCapabilityInvocation} = require('http-signature-zcap-invoke');

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
    it('throws error on no sequence in postKeystoreBody validation',
      async () => {
        const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
        const handle = 'testKey1';

        const capabilityAgent = await CapabilityAgent
          .fromSecret({secret, handle});
        const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;
        const url = `${kmsBaseUrl}/keystores`;
        const config = {
          controller: capabilityAgent.id
        };

        let err;
        let result;
        try {
          result = await httpClient.post(url, {agent, json: config});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.message.should.equal(
          'A validation error occured in the \'postKeystoreBody\' validator.');
      });
    it('gets a keystore', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      const keystore = await helpers.createKeystore({capabilityAgent});
      let err;
      let result;
      try {
        result = await helpers.getKeystore({id: keystore.id});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.id.should.equal(keystore.id);
    });
    it('finds a keystore', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';
      const referenceId =
        'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      const keystore = await helpers.createKeystore({
        capabilityAgent, referenceId});
      let err;
      let result;
      try {
        result = await helpers.findKeystore({
          controller: keystore.controller, referenceId});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.id.should.equal(keystore.id);
      result.controller.should.equal(keystore.controller);
      result.referenceId.should.equal(keystore.referenceId);
    });
    it('throws error on no controller in getKeystoreQuery validation',
      async () => {
        const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
        const handle = 'testKey1';
        const referenceId =
          'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg';

        const capabilityAgent = await CapabilityAgent
          .fromSecret({secret, handle});

        const keystore = await helpers.createKeystore({
          capabilityAgent, referenceId});

        const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;
        const url = `${kmsBaseUrl}/keystores` +
          `/?r?controller=${keystore.controller}`;

        let err;
        let result;
        try {
          result = await httpClient.get(url, {agent});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.message.should.equal(
          'A validation error occured in the \'getKeystoreQuery\' validator.');
      });
    it('throws error on no referenceId in getKeystoreQuery validation',
      async () => {
        const referenceId =
          'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg';

        const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;
        const url = `${kmsBaseUrl}/keystores` +
          `/?referenceId=${referenceId}`;

        let err;
        let result;
        try {
          result = await httpClient.get(url, {agent});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.message.should.equal(
          'A validation error occured in the \'getKeystoreQuery\' validator.');
      });
    it('throws error with no invoker in zcap validation', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});
      const keystore = await helpers.createKeystore({
        capabilityAgent});

      const url = `${keystore.id}/authorizations`;

      const zcap = mockData.zcaps.zero;
      delete zcap.invoker;

      let err;
      let result;
      try {
        result = await httpClient.post(url, {agent, json: zcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.message.should.equal(
        'A validation error occured in the \'zcap\' validator.');
    });
    // FIXME: this test uses the obsolete /recovery endpoint
    it.skip('throws error with no controller in postRecoverBody validation',
      async () => {
        const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
        const handle = 'testKey1';

        const capabilityAgent = await CapabilityAgent
          .fromSecret({secret, handle});
        const keystore = await helpers.createKeystore({
          capabilityAgent});

        const url = `${keystore.id}/recover`;

        const config = {
          '@context': 'https://w3id.org/security/v2',
        };

        let err;
        let result;
        try {
          result = await httpClient.post(url, {agent, json: config});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.message.should.equal(
          'A validation error occured in the \'postRecoverBody\' validator.');
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
      err.data.message.should.contain('Permission denied. Expected host');
    });
    it('updates a keystore config', async () => {
      const secret = '69ae7dc3-1d6d-4ff9-9cc0-c07b43d2006b';
      const handle = 'testKeyUpdate';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      const secret2 = 'ac36ef8e-560b-4f6c-a454-6bfcb4e31a76';
      const handle2 = 'testKeyUpdate2';

      const capabilityAgent2 = await CapabilityAgent
        .fromSecret({secret: secret2, handle: handle2});

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

      const {id: url} = result;
      const newConfig = {
        // did:key:z6MknP29cPcQ7G76MWmnsuEEdeFya8ij3fXvJcTJYLXadmp9
        controller: capabilityAgent2.id,
      };

      const headers = await signCapabilityInvocation({
        url, method: 'post',
        headers: DEFAULT_HEADERS,
        json: newConfig,
        capability: 'urn:zcap:root:' + encodeURIComponent(url),
        invocationSigner: capabilityAgent.signer,
        capabilityAction: 'write'
      });

      err = null;
      result = null;
      try {
        result = await httpClient.post(url, {agent, headers, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.data.should.have.keys(['controller', 'id', 'sequence']);
      result.data.controller.should.equal(capabilityAgent2.id);
      result.data.id.should.equal(url);
      result.data.sequence.should.equal(1);
    });
  });
});
