/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const helpers = require('./helpers');
const jsigs = require('jsonld-signatures');
const {CapabilityDelegation} = require('@digitalbazaar/zcapld');
const {AsymmetricKey, CapabilityAgent, KmsClient, KeystoreAgent} =
  require('@digitalbazaar/webkms-client');
const {util: {uuid}} = bedrock;
const {
  purposes: {AssertionProofPurpose},
  sign,
} = jsigs;
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');
const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {CONTEXT_URL: ZCAP_CONTEXT_URL} = require('zcap-context');
const {documentLoader} = require('bedrock-jsonld-document-loader');

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

describe('revocations API with ipAllowList', () => {
  let aliceCapabilityAgent;
  let aliceKeystoreConfig;
  let aliceKeystoreAgent;
  let bobCapabilityAgent;
  let carolCapabilityAgent;

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'alice';
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    aliceKeystoreConfig = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent});
    const {httpsAgent} = brHttpsAgent;
    const kmsClient = new KmsClient({httpsAgent});
    aliceKeystoreAgent = new KeystoreAgent({
      capabilityAgent: aliceCapabilityAgent,
      keystoreId: aliceKeystoreConfig.id,
      kmsClient,
    });
  });

  // generate a capability agent for Bob
  before(async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bob';
    bobCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
  });

  // generate a capability agent for Carol
  before(async () => {
    const secret = 'ae806cd9-2765-4232-b955-01e1024ac032';
    const handle = 'carol';
    carolCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
  });

  it('returns NotAllowedError for invalid source IP', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(aliceKey);

    // next, delegate authority to bob to use alice's key
    const bobZcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Bob's zcap
      controller: bobCapabilityAgent.id,
      // there is no root capability at the `invocationTarget` location,
      // so this alternate URL is used that will automatically generate a
      // root capability
      parentCapability: ZCAP_ROOT_PREFIX +
        encodeURIComponent(aliceKeystoreAgent.keystoreId),
      allowedAction: 'sign',
      invocationTarget: {
        publicAlias: aliceKey.id,
        id: aliceKey.kmsId,
        type: aliceKey.type,
      }
    };

    // Alice now signs the capability delegation that allows Bob to `sign`
    // with her key.
    const signedCapabilityFromAliceToBob = await _delegate({
      capabilityChain: [
        // Alice's root keystore zcap is always the first
        // item in the `capabilityChain`
        bobZcap.parentCapability
      ],
      signer: aliceCapabilityAgent.getSigner(),
      zcap: bobZcap,
      documentLoader
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAliceToBob,
      // bob signs the invocation to use alice's key (and alice's key will
      // sign the document)
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    bobSignedDocument.should.have.property('@context');
    bobSignedDocument.should.have.property('referenceId');
    bobSignedDocument.should.have.property('proof');
    bobSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    bobSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob has successfully used alice's key to sign a document!

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Carol's zcap
      controller: carolCapabilityAgent.id,
      parentCapability: signedCapabilityFromAliceToBob.id,
      allowedAction: 'sign',
      invocationTarget: signedCapabilityFromAliceToBob.invocationTarget
    };

    // finish bob's delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        signedCapabilityFromAliceToBob.parentCapability,
        signedCapabilityFromAliceToBob
      ],
      signer: bobCapabilityAgent.getSigner(),
      zcap: carolZcap,
      documentLoader
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromBobToCarol,
      // carol signs the invocation to use alice's key (and alice's key
      // will sign the document)
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('referenceId');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // update Alice's keystore config to include ipAllowList
    aliceKeystoreConfig.sequence++;
    aliceKeystoreConfig.ipAllowList = ['8.8.8.8/32'];

    const {success} = await aliceKeystoreAgent.updateConfig(
      {config: aliceKeystoreConfig});
    success.should.equal(true);

    // Bob now submits a revocation to revoke the capability he gave to Carol.

    // in practice bob is going to locate the capability he gave to carol
    // by way of bedrock-web-zcap-storage

    // this adds a revocation for Carol's `sign` capability on Alice's
    // kms system

    // this request should fails because the request does not originate from
    // an IP in the `ipAllowList` on Alice's keystore.
    let err;
    let result;
    try {
      result = await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bob is revoking the capability he gave to carol
        invocationSigner: bobCapabilityAgent.getSigner()
      });
    } catch(e) {
      err = e;
    }
    should.not.exist(result);
    should.exist(err);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
    err.data.message.should.contain('Source IP');
  });
});

async function _delegate({zcap, signer, capabilityChain, documentLoader}) {
  // attach capability delegation proof
  return sign(zcap, {
    suite: new Ed25519Signature2020({
      signer
    }),
    purpose: new CapabilityDelegation({capabilityChain}),
    compactProof: false,
    documentLoader
  });
}

async function _signWithDelegatedKey({capability, doc, invocationSigner}) {
  const {httpsAgent} = brHttpsAgent;
  const delegatedSigningKey = new AsymmetricKey({
    capability,
    invocationSigner,
    kmsClient: new KmsClient({httpsAgent})
  });
  const suite = new Ed25519Signature2020({
    signer: delegatedSigningKey
  });

  doc = doc || {
    '@context': ZCAP_CONTEXT_URL,
    // just using a term out of the zcap context
    referenceId: 'testId'
  };

  return sign(doc, {
    documentLoader,
    suite,
    purpose: new AssertionProofPurpose(),
  });
}

async function _revokeDelegatedCapability({
  capability, capabilityToRevoke, invocationSigner
}) {
  const {httpsAgent} = brHttpsAgent;
  const kmsClient = new KmsClient({httpsAgent});
  await kmsClient.revokeCapability({
    capabilityToRevoke,
    capability,
    invocationSigner
  });
}

async function _setKeyId(key) {
  // the keyDescription is required to get fingerprint
  const keyDescription = await key.getKeyDescription();
  // create public ID (did:key) for bob's key
  const fingerprint =
    (await Ed25519VerificationKey2020.from(keyDescription)).fingerprint();
  // invocationTarget.publicAlias = `did:key:${fingerprint}`;
  key.id = `did:key:${fingerprint}#${fingerprint}`;
}
