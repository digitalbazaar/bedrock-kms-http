/*
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {createRequire} from 'node:module';
import {documentLoader} from '@bedrock/jsonld-document-loader';
import {getAppIdentity} from '@bedrock/app-identity';
import {httpsAgent} from '@bedrock/https-agent';
import jsigs from 'jsonld-signatures';
import uuid from 'uuid-random';
const require = createRequire(import.meta.url);
const {AsymmetricKey, CapabilityAgent, KeystoreAgent, KmsClient} =
  require('@digitalbazaar/webkms-client');
const {
  CapabilityDelegation,
  constants: zcapConstants
} = require('@digitalbazaar/zcap');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {ZcapClient} = require('@digitalbazaar/ezcap');

const {purposes: {AssertionProofPurpose}} = jsigs;
const {ZCAP_CONTEXT_URL} = zcapConstants;

export async function createMeter({capabilityAgent} = {}) {
  // create signer using the application's capability invocation key
  const {keys: {capabilityInvocationKey}} = getAppIdentity();

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityInvocationKey.signer(),
    SuiteClass: Ed25519Signature2020
  });
  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller: capabilityAgent.id,
    product: {
      // mock ID for webkms service product
      id: 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
}

export async function createKeystore({
  capabilityAgent, ipAllowList, referenceId, meterId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`,
  kmsModule = 'ssm-v1',
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter({capabilityAgent}));
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
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
    invocationSigner: capabilityAgent.getSigner(),
    httpsAgent
  });
}

export async function createKeystoreAgent({
  handle, ipAllowList, secret, kmsClientHeaders = {}
}) {
  const capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

  let err;
  let keystore;
  try {
    keystore = await createKeystore({capabilityAgent, ipAllowList});
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
}

export async function getKeystore({id, capabilityAgent}) {
  const kmsClient = new KmsClient({keystoreId: id, httpsAgent});
  const invocationSigner = capabilityAgent.getSigner();
  return kmsClient.getKeystore({invocationSigner});
}

export async function delegate({
  parentCapability, controller, invocationTarget, expires, allowedAction,
  delegator, purposeOptions = {}
}) {
  const newCapability = {
    '@context': ZCAP_CONTEXT_URL,
    id: `urn:zcap:${uuid()}`,
    controller,
    parentCapability: parentCapability.id || parentCapability,
    invocationTarget: invocationTarget || parentCapability.invocationTarget,
    expires: expires || parentCapability.expires ||
      new Date(Date.now() + 5000).toISOString().slice(0, -5) + 'Z',
    allowedAction: allowedAction || parentCapability.allowedAction
  };
  // attach capability delegation proof
  return jsigs.sign(newCapability, {
    documentLoader,
    purpose: new CapabilityDelegation({parentCapability, ...purposeOptions}),
    suite: new Ed25519Signature2020({signer: delegator.getSigner()}),
  });
}

export async function revokeDelegatedCapability({
  capabilityToRevoke, invocationSigner
}) {
  const kmsClient = new KmsClient({httpsAgent});
  await kmsClient.revokeCapability({
    capabilityToRevoke,
    invocationSigner
  });
}

export async function signWithDelegatedKey({
  capability, doc, invocationSigner
}) {
  const delegatedSigningKey = await AsymmetricKey.fromCapability({
    capability,
    invocationSigner,
    kmsClient: new KmsClient({httpsAgent})
  });
  const suite = new Ed25519Signature2020({signer: delegatedSigningKey});

  doc = doc || {'example:foo': 'test'};

  return jsigs.sign(doc, {
    documentLoader,
    purpose: new AssertionProofPurpose(),
    suite
  });
}
