/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent, KeystoreAgent, KmsClient} =
  require('@digitalbazaar/webkms-client');
const {httpsAgent} = require('bedrock-https-agent');

exports.createMeter = async ({} = {}) => {
  // FIXME: first create a meter and get a meter zcap for it
  const meterId = `${bedrock.config.server.baseUri}/meters/` +
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
};

exports.createKeystore = async ({
  capabilityAgent, ipAllowList, referenceId, meterCapability,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`,
  kmsModule = 'ssm-v1',
}) => {
  if(!meterCapability) {
    // create a meter for the keystore
    ({meterCapability} = await exports.createMeter());
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterCapability,
    kmsModule
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }

  return KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    httpsAgent
  });
};

exports.createKeystoreAgent = async ({
  handle, ipAllowList, secret, keyType, kmsClientHeaders = {}
}) => {
  const capabilityAgent = await CapabilityAgent.fromSecret({
    secret, handle, keyType});

  let err;
  let keystore;
  try {
    keystore = await exports.createKeystore({capabilityAgent, ipAllowList});
  } catch(e) {
    err = e;
  }
  assertNoError(err);

  // create kmsClient only required because we need to use httpsAgent
  // that accepts self-signed certs used in test suite
  const kmsClient = new KmsClient(
    {httpsAgent, defaultHeaders: kmsClientHeaders});
  const keystoreAgent = new KeystoreAgent({
    capabilityAgent,
    keystoreId: keystore.id,
    kmsClient
  });

  return keystoreAgent;
};

exports.getKeystore = async ({id, capabilityAgent}) => {
  const kmsClient = new KmsClient({keystoreId: id, httpsAgent});
  const invocationSigner = capabilityAgent.getSigner();
  return kmsClient.getKeystore({invocationSigner});
};

// FIXME: consider removal
/*exports.findKeystore = async ({
  controller, referenceId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`
}) => {
  const url = `${kmsBaseUrl}/keystores` +
    `/?controller=${controller}&referenceId=${referenceId}`;
  return KmsClient.findKeystore({
    url, controller, referenceId, httpsAgent
  });
};
*/
