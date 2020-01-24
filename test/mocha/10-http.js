/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
// const {config, util: {uuid}} = bedrock;
const {ControllerKey, KmsClient} = require('webkms-client');

describe('bedrock-kms-http API', () => {
  describe('keystores', () => {
    it('creates a keystore', async () => {
      const secret = ' b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const {httpsAgent} = brHttpsAgent;
      // keystore in the kmsClient is set later
      const kmsClient = new KmsClient({httpsAgent});

      const controllerKey = await ControllerKey.fromSecret({
        secret, handle, kmsClient
      });

      let err;
      let result;
      try {
        result = await _createKeystore({controllerKey});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: controllerKeyId} = controllerKey;
      result.should.have.property('controller');
      result.controller.should.equal(controllerKeyId);
      result.should.have.property('invoker');
      result.invoker.should.equal(controllerKeyId);
      result.should.have.property('delegator');
      result.delegator.should.equal(controllerKeyId);
    });
  });

});

async function _createKeystore({controllerKey, recoveryHost, referenceId}) {
  // create keystore
  const config = {
    sequence: 0,
    controller: controllerKey.id,
    invoker: controllerKey.id,
    delegator: controllerKey.id
  };
  if(recoveryHost) {
    config.invoker = [config.invoker, recoveryHost];
  }
  if(referenceId) {
    config.referenceId = referenceId;
  }
  const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;
  const {httpsAgent} = brHttpsAgent;
  return await KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    httpsAgent,
  });
}
