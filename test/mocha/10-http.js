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
        '@context': 'https://w3id.org/security/v2',
        type: 'GenerateKeyOperation',
        invocationTarget: {
          id: 'idFoo',
          type: 'typeFoo',
          controller: 'controllerFoo',
        },
        proof: {
          type: uuid(),
          capability: uuid(),
          created: uuid(),
          jws: uuid(),
          proofPurpose: 'capabilityInvocation',
          verificationMethod: uuid()
        }
      };
      const response = await api.post(`/foo/bar`, operation, {httpsAgent});
      console.log('ERROR', response.data);
      // should.exist(err.response);
      // err.response.status.should.equal(400);
    });
    it('should fail to execute a "generateKey" operation', async () => {
    });
  });
});
