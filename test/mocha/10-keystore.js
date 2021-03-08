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
      result.should.have.keys(['controller', 'id', 'sequence']);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('creates a keystore including proper ipAllowList', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      const ipAllowList = ['127.0.0.1/32'];

      let err;
      let result;
      try {
        result = await helpers.createKeystore({capabilityAgent, ipAllowList});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys(['controller', 'id', 'ipAllowList', 'sequence']);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
      result.ipAllowList.should.eql(ipAllowList);
    });
    it('returns error on invalid ipAllowList', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      // this is no a valid CIDR
      const ipAllowList = ['127.0.0.1/33'];

      let err;
      let result;
      try {
        result = await helpers.createKeystore({capabilityAgent, ipAllowList});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should match pattern');
      error.details.path.should.equal('.ipAllowList[0]');
    });
    it('returns error on invalid ipAllowList', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle});

      // an empty allow list is invalid
      const ipAllowList = [];

      let err;
      let result;
      try {
        result = await helpers.createKeystore({capabilityAgent, ipAllowList});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should NOT have fewer than 1 items');
      error.details.path.should.equal('.ipAllowList');
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
    // FIXME: this test uses the obsolete /recovery endpoint, this test will
    // be refactored along with issue #45.
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
    describe('update keystore config', () => {
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
          id: url,
          sequence: 1,
        };

        const headers = await signCapabilityInvocation({
          url, method: 'post',
          headers: DEFAULT_HEADERS,
          json: newConfig,
          capability: 'urn:zcap:root:' + encodeURIComponent(url),
          invocationSigner: capabilityAgent.getSigner(),
          capabilityAction: 'write'
        });

        err = null;
        result = null;
        try {
          result = await httpClient.post(
            url, {agent, headers, json: newConfig});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result.data);
        result.status.should.equal(200);
        result.data.should.have.keys(['config', 'success']);
        result.data.success.should.be.a('boolean');
        result.data.success.should.equal(true);
        result.data.config.should.eql(newConfig);

        // retrieve the keystore config to confirm update was effective
        err = null;
        result = null;
        try {
          result = await helpers.getKeystore({id: newConfig.id});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.eql(newConfig);
      });
      it('rejects config update for an invalid zcap', async () => {
        const secret = 'd852a72d-013f-4dd6-8ba2-588aaf601b66';
        const handle = 'testKeyUpdate';

        const capabilityAgent = await CapabilityAgent
          .fromSecret({secret, handle});

        const secret2 = '4decd824-50e6-45bf-a79e-41af397f499f';
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
          controller: capabilityAgent2.id,
          id: url,
          sequence: 1,
        };

        // the capability invocation here is signed by capabilityAgent2 which
        // is not the controller of the keystore
        const headers = await signCapabilityInvocation({
          url, method: 'post',
          headers: DEFAULT_HEADERS,
          json: newConfig,
          capability: 'urn:zcap:root:' + encodeURIComponent(url),
          invocationSigner: capabilityAgent2.signer,
          capabilityAction: 'write'
        });

        err = null;
        result = null;
        try {
          result = await httpClient.post(
            url, {agent, headers, json: newConfig});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.status.should.equal(403);
      });
      it('rejects config update with an invalid sequence', async () => {
        const secret = 'a8256be9-beea-4b05-9fc2-7ad4c1a391e4';
        const handle = 'testKeyUpdate';

        const capabilityAgent = await CapabilityAgent
          .fromSecret({secret, handle});

        const secret2 = 'd2896f13-fed0-4122-b984-326dc29c927a';
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
          id: url,
          // the proper sequence would be 1
          sequence: 10,
        };

        const headers = await signCapabilityInvocation({
          url, method: 'post',
          headers: DEFAULT_HEADERS,
          json: newConfig,
          capability: 'urn:zcap:root:' + encodeURIComponent(url),
          invocationSigner: capabilityAgent.getSigner(),
          capabilityAction: 'write'
        });

        err = null;
        result = null;
        try {
          result = await httpClient.post(
            url, {agent, headers, json: newConfig});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.status.should.equal(409);
        err.data.message.should.contain('sequence does not match');
        err.data.type.should.equal('InvalidStateError');
        err.data.details.should.have.keys(['id', 'sequence', 'httpStatusCode']);
      });
      describe('updates with ipAllowList', () => {
        it('updates a keystore config with ipAllowList', async () => {
          const secret = 'e44c4869-2fd7-4f7f-a123-addb05ec9c2a';
          const handle = 'testKeyUpdate';

          const capabilityAgent = await CapabilityAgent
            .fromSecret({secret, handle});

          const secret2 = '82ef7805-21ed-43bb-a604-4ccc7a06eacc';
          const handle2 = 'testKeyUpdate2';

          const capabilityAgent2 = await CapabilityAgent
            .fromSecret({secret: secret2, handle: handle2});

          const ipAllowList = ['127.0.0.1/32'];

          let err;
          let result;
          try {
            result = await helpers.createKeystore(
              {capabilityAgent, ipAllowList});
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
            id: url,
            ipAllowList,
            sequence: 1,
          };

          const headers = await signCapabilityInvocation({
            url, method: 'post',
            headers: DEFAULT_HEADERS,
            json: newConfig,
            capability: 'urn:zcap:root:' + encodeURIComponent(url),
            invocationSigner: capabilityAgent.getSigner(),
            capabilityAction: 'write'
          });

          err = null;
          result = null;
          try {
            result = await httpClient.post(
              url, {agent, headers, json: newConfig});
          } catch(e) {
            err = e;
          }
          assertNoError(err);
          should.exist(result.data);
          result.status.should.equal(200);
          result.data.should.have.keys(['config', 'success']);
          result.data.success.should.be.a('boolean');
          result.data.success.should.equal(true);
          result.data.config.should.eql(newConfig);

          // retrieve the keystore config to confirm update was effective
          err = null;
          result = null;
          try {
            result = await helpers.getKeystore({id: newConfig.id});
          } catch(e) {
            err = e;
          }
          assertNoError(err);
          should.exist(result);
          result.should.eql(newConfig);
        });
        it('returns NotAllowedError for invalid source IP', async () => {
          const secret = '481f41a0-af87-407f-b7ec-38f1fbb10d12';
          const handle = 'testKeyUpdate';

          const capabilityAgent = await CapabilityAgent
            .fromSecret({secret, handle});

          const secret2 = 'ddbbbc38-eb27-4238-8b84-382ada29b8c0';
          const handle2 = 'testKeyUpdate2';

          const capabilityAgent2 = await CapabilityAgent
            .fromSecret({secret: secret2, handle: handle2});

          const ipAllowList = ['8.8.8.8/32'];

          let err;
          let result;
          try {
            result = await helpers.createKeystore(
              {capabilityAgent, ipAllowList});
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
            id: url,
            ipAllowList,
            sequence: 1,
          };

          const headers = await signCapabilityInvocation({
            url, method: 'post',
            headers: DEFAULT_HEADERS,
            json: newConfig,
            capability: 'urn:zcap:root:' + encodeURIComponent(url),
            invocationSigner: capabilityAgent.getSigner(),
            capabilityAction: 'write'
          });

          err = null;
          result = null;
          try {
            result = await httpClient.post(
              url, {agent, headers, json: newConfig});
          } catch(e) {
            err = e;
          }
          should.not.exist(result);
          should.exist(err);
          err.status.should.equal(403);
          err.data.type.should.equal('NotAllowedError');
        });
      }); // updates with ipAllowList
    }); // end update keystore config
  });
});
