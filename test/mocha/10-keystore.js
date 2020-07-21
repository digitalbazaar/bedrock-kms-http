/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent} = require('webkms-client');
const helpers = require('./helpers');
const brHttpsAgent = require('bedrock-https-agent');
const {httpClient} = require('@digitalbazaar/http-client');
const mockData = require('./mock.data');

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
    it('throws error on no sequence in postKeystore validation', async () => {
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
        const {agent} = brHttpsAgent;
        result = await httpClient.post(url, {agent, json: config});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.message.should.equal(
        'A validation error occured in the \'postKeystore\' validator.');
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
    it('throws error on no controller in findKeystore validation', async () => {
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
        const {agent} = brHttpsAgent;
        result = await httpClient.get(url, {agent});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.message.should.equal(
        'A validation error occured in the \'findKeystore\' validator.');
    });
    it('throws error on no referenceId in findKeystore validation',
      async () => {
        const referenceId =
         'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg';

        const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;
        const url = `${kmsBaseUrl}/keystores` +
          `/?referenceId=${referenceId}`;

        let err;
        let result;
        try {
          const {agent} = brHttpsAgent;
          result = await httpClient.get(url, {agent});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.message.should.equal(
          'A validation error occured in the \'findKeystore\' validator.');
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
        const {agent} = brHttpsAgent;
        result = await httpClient.post(url, {agent, json: zcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.message.should.equal(
        'A validation error occured in the \'zcap\' validator.');
    });
    it('throws error with no controller in recovery validation',
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
          const {agent} = brHttpsAgent;
          result = await httpClient.post(url, {agent, json: config});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.data.message.should.equal(
          'A validation error occured in the \'recovery\' validator.');
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
  });
});
