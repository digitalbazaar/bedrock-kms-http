/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {create} = require('apisauce');
const {config, util: {uuid}} = bedrock;

const baseURL = `${config.server.baseUri}/kms`;
const {httpsAgent} = brHttpsAgent;
const api = create({baseURL, httpsAgent});

describe('bedrock-kms-http API', () => {
  describe('operations', () => {
    it('should execute a "generateKey" operation', async () => {
      const operation = {
        '@context': config.constants.SECURITY_CONTEXT_V2_URL,
        type: 'GenerateKeyOperation',
        invocationTarget: {
          id: `https://example.com/kms/${uuid()}`,
          type: 'Ed25519VerificationKey2018',
          controller: 'controllerFoo',
        },
        kmsModule: 'ssm-v1',
        // TODO: proofs are not validated
        proof: {
          type: uuid(),
          capability: uuid(),
          created: uuid(),
          jws: uuid(),
          proofPurpose: 'capabilityInvocation',
          verificationMethod: uuid()
        }
      };
      // this request simulates a proxied request where the hostname in the
      // invocationTarget.id does not match the local hostname
      const path = operation.invocationTarget.id.split('/').slice(-1).join('/');
      const response = await api.post(path, operation);
      console.log('JJJJJJJ', response);

      should.not.exist(response.problem);
      should.exist(response.data);
      response.data.should.be.an('object');
      Object.keys(response.data).should.have.same.members(
        ['id', 'type', 'publicKeyBase58']);
    });
    it.skip('should fail to execute a "generateKey" operation', async () => {
    });
  });
  describe('requireAuthentication enabled', () => {
    before(() => config['kms-http'].requireAuthentication = true);
    after(() => config['kms-http'].requireAuthentication = false);
    it('NotAllowedError on unauthenticated GenerateKeyOperation', async () => {
      const operation = {
        '@context': config.constants.SECURITY_CONTEXT_V2_URL,
        type: 'GenerateKeyOperation',
        invocationTarget: {
          id: `https://example.com/kms/${uuid()}`,
          type: 'Ed25519VerificationKey2018',
          controller: 'controllerFoo',
        },
        kmsModule: 'ssm-v1',
        // TODO: proofs are not validated
        proof: {
          type: uuid(),
          capability: uuid(),
          created: uuid(),
          jws: uuid(),
          proofPurpose: 'capabilityInvocation',
          verificationMethod: uuid()
        }
      };
      const path = operation.invocationTarget.id.split('/').slice(-1).join('/');
      const response = await api.post(path, operation);
      should.exist(response.problem);
      response.problem.should.equal('CLIENT_ERROR');
      response.status.should.equal(400);
      should.exist(response.data);
      response.data.type.should.equal('NotAllowedError');
    });
  });
});
