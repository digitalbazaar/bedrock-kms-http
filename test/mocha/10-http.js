/*
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const https = require('https');
const {create} = require('apisauce');
const {config, util: {uuid}} = bedrock;
// allow self-signed cert for tests
const httpsAgent = new https.Agent({rejectUnauthorized: false});

const baseURL = `${config.server.baseUri}/kms`;
const api = create({baseURL});

describe('bedrock-kms-http API', () => {
  describe('operations', () => {
    it('should execute a "generateKey" operation', async () => {
      const operation = {
        '@context': config.constants.SECURITY_CONTEXT_V2_URL,
        type: 'GenerateKeyOperation',
        invocationTarget: {
          id: `https://example.com/kms/ssm-v1/${uuid()}`,
          type: 'Ed25519VerificationKey2018',
          controller: 'controllerFoo',
        },
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
      const path = operation.invocationTarget.id.split('/').slice(-2).join('/');
      const response = await api.post(path, operation, {httpsAgent});
      should.not.exist(response.problem);
      should.exist(response.data);
      response.data.should.be.an('object');
      Object.keys(response.data).should.have.same.members(
        ['id', 'type', 'publicKeyBase58']);
    });
    it.skip('should fail to execute a "generateKey" operation', async () => {
    });
  });
});
