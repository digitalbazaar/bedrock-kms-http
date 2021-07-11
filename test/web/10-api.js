/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const pMap = require('p-map');
const uuid = require('uuid-random');
const {CapabilityAgent, KeystoreAgent, KmsClient} =
  require('@digitalbazaar/webkms-client');

describe('bedrock-kms-http HMAC operations', () => {
  describe('Sha256HmacKey2019', () => {
    let hmac;
    before(async () => {
      const secret = 'b07e6b31-d910-438e-9a5f-08d945a5f676';
      const handle = 'testKey1';

      const capabilityAgent = await CapabilityAgent
        .fromSecret({secret, handle, keyType: 'Ed25519VerificationKey2020'});

      let err;
      let keystore;
      try {
        keystore = await _createKeystore({capabilityAgent});
      } catch(e) {
        err = e;
      }
      should.not.exist(err);

      // create kmsClient only required because we need to use httpsAgent
      // that accepts self-signed certs used in test suite
      const kmsClient = new KmsClient();
      const keystoreAgent = new KeystoreAgent({
        capabilityAgent,
        keystoreId: keystore.id,
        kmsClient
      });
      hmac = await keystoreAgent.generateKey({type: 'hmac'});
    });
    it('successfully signs', async () => {
      const data = new TextEncoder('utf-8').encode('hello');
      let err;
      let result;
      try {
        result = await hmac.sign({data});
      } catch(e) {
        err = e;
      }
      should.not.exist(err);
      should.exist(result);
      result.should.be.a('string');
    });

    describe('bulk operations', () => {
      const operationCount = 10000;
      const vData = [];
      before(async () => {
        for(let i = 0; i < operationCount; ++i) {
          let v = '';
          for(let n = 0; n < 100; ++n) {
            v += uuid();
          }
          vData.push(new TextEncoder('utf-8').encode(v));
        }
      });
      it(`performs ${operationCount} signatures`, async function() {
        this.timeout(0);
        const startTime = Date.now();
        let result;
        let err;
        try {
          result = await pMap(
            vData, data => hmac.sign({data}), {concurrency: 30});
        } catch(e) {
          err = e;
        }
        should.not.exist(err);
        should.exist(result);
        result.should.be.an('array');
        result.should.have.length(operationCount);
        const elapsedTime = Date.now() - startTime;
        // NOTE: reporter in karma does not report elapsed time for individual
        // tests, this logging is intentional
        console.log('ELAPSED TIME', elapsedTime);
      });
    }); // end bulk operations
  });
});

async function _createKeystore({capabilityAgent, referenceId}) {
  const {meterCapability} = await createMeter();

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    kmsModule: 'ssm-v1',
    meterCapability
  };

  if(referenceId) {
    config.referenceId = referenceId;
  }
  return KmsClient.createKeystore({config});
}

async function createMeter({} = {}) {
  // FIXME: first create a meter and get a meter zcap for it
  const meterId = `https://localhost:18443/meters/` +
    'zSLHvnwnX22DCQ2xo9pX5U6/usage';
  const did = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
  const parentCapability = `urn:zcap:root:${encodeURIComponent(meterId)}`;
  const meterCapability = {
    // FIXME: use constant
    '@context': [
      'https://w3id.org/zcap/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    //id: `urn:${uuid()}`,
    id: 'urn:6ab157aa-e0e1-11eb-af0f-10bf48838a41',
    invocationTarget: meterId,
    controller: did,
    allowedAction: ['read', 'write'],
    parentCapability,
    // FIXME: use second precision
    expires: new Date().toISOString(),
    proof: {
      type: 'Ed25519Signature2020',
      verificationMethod:
        `${did}#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH`,
      // FIXME: use second precision
      created: new Date().toISOString(),
      capabilityChain: [parentCapability],
      proofPurpose: 'capabilityDelegation',
      proofValue: 'MOCK'
    }
  };
  return {meterCapability};
}
