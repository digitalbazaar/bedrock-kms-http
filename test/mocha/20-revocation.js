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

describe('revocations API', () => {
  let aliceCapabilityAgent;
  let aliceKeystoreAgent;
  let bobCapabilityAgent;
  let bobKeystoreAgent;
  let bobKey;
  let carolCapabilityAgent;
  let carolKey;
  let carolKeystoreAgent;

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'testKey2';
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent});
    const {httpsAgent} = brHttpsAgent;
    const kmsClient = new KmsClient({httpsAgent});
    aliceKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: aliceCapabilityAgent, keystoreId, kmsClient});
  });

  // generate a keystore for Bob
  before(async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bobKey';
    bobCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent: bobCapabilityAgent});
    try {
      const {httpsAgent} = brHttpsAgent;
      const kmsClient = new KmsClient({httpsAgent});
      bobKeystoreAgent = new KeystoreAgent(
        {capabilityAgent: bobCapabilityAgent, keystoreId, kmsClient});
    } catch(e) {
      assertNoError(e);
    }
    try {
      bobKey = await bobKeystoreAgent.generateKey({type: 'asymmetric'});
    } catch(e) {
      assertNoError(e);
    }
    await _setKeyId(bobKey);
  });

  // generate a keystore for Carol
  before(async () => {
    const secret = 'ae806cd9-2765-4232-b955-01e1024ac032';
    const handle = 'carolKey';
    const {httpsAgent} = brHttpsAgent;
    carolCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent: carolCapabilityAgent});
    const kmsClient = new KmsClient({httpsAgent});
    carolKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: carolCapabilityAgent, keystoreId, kmsClient});

    carolKey = await carolKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(carolKey);
  });

  it('successfully revokes a delegation', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(aliceKey);
    // next, delegate authority to bob to use alice's key
    const zcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Bob's capabilityInvocation key that will be used to invoke
      // the capability
      invoker: bobKey.id,
      // this provides Bob the ability to delegate the capability again to
      // Carol later
      delegator: bobKey.id,
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
    const signer = aliceCapabilityAgent.getSigner();
    const signedCapabilityFromAlice = await _delegate({
      capabilityChain: [
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer,
      zcap,
      documentLoader
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAlice,
      invokeKey: bobKey,
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
      invoker: carolKey.id,
      // the capability Alice gave to Bob
      parentCapability: zcap.id,
      // this is where we need to ensure the allowedAction here is included
      // in the allowedAction of the parentCapability, there is an issue in
      // zcapld for this.
      allowedAction: 'sign',
      invocationTarget: zcap.invocationTarget,
    };

    // finish bobs delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
        zcap,
      ],
      signer: bobKey,
      zcap: carolZcap,
      documentLoader
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromBobToCarol,
      invokeKey: carolKey,
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('referenceId');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob now submits a revocation to revoke the capability he gave to Carol.

    // in practice bob is going to locate the capability he gave to carol
    // by way of bedrock-web-zcap-storage

    // this adds a revocation for Carol's `sign` capability on Alice's
    // kms system
    await _revokeDelegatedCapability({
      // the `sign` capability that Bob gave to Carol
      capabilityToRevoke: signedCapabilityFromBobToCarol,
      // bobKey is the `invoker` in `signedBobRevocationZcap`
      invocationSigner: bobKey
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bobKey is the `delegator` in `signedCapabilityFromBobToCarol`,
        // so invoke using it to revoke carol's zcap
        invocationSigner: bobKey
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.status.should.equal(403);
    should.exist(err.data);
    const {data} = err;
    data.type.should.equal('NotAllowedError');

    // Bob would then update his delegation record in an EDV to indicate that
    // the delegation is now revoked. This is just a housekeeping measure,
    // Carol's capability is revoked on Alice's system and is no longer valid.

    // demonstrate that Carol can no longer use Alice's key for signing.
    let result;
    err = null;
    try {
      result = await _signWithDelegatedKey({
        capability: signedCapabilityFromBobToCarol,
        invokeKey: carolKey,
      });
    } catch(e) {
      err = e;
    }
    should.not.exist(result);
    should.exist(err);
    should.exist(err.data);
    err.data.type.should.equal('NotAllowedError');
  });
  it('throws error on zcap that was not properly delegated', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(aliceKey);

    // next, delegate authority to bob to use alice's key
    const zcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Bob's capabilityInvocation key that will be used to invoke
      // the capability
      invoker: bobKey.id,
      // this provides Bob the ability to delegate the capability again to
      // Carol later
      delegator: bobKey.id,
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

    // Alice now DOES NOT sign the capability delegation; Bob is NOT
    // allowed to `sign` with her key.

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: carolKey.id,
      // the capability Alice gave to Bob
      parentCapability: zcap.id,
      // this is where we need to ensure the allowedAction here is included
      // in the allowedAction of the parentCapability, there is an issue in
      // zcapld for this.
      allowedAction: 'sign',
      invocationTarget: zcap.invocationTarget
    };

    // finish bobs delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
        zcap//signedCapabilityFromAlice,
      ],
      signer: bobKey,
      zcap: carolZcap,
      documentLoader
    });

    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bobKey is the `delegator` in `signedCapabilityFromBobToCarol`,
        // so invoke using it to revoke carol's zcap
        invocationSigner: bobKey
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.data.type.should.equal('NotAllowedError');
  });
  it('throws error on zcap validator', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(aliceKey);

    // next, delegate authority to bob to use alice's key
    const zcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Bob's capabilityInvocation key that will be used to invoke
      // the capability
      invoker: bobKey.id,
      // this provides Bob the ability to delegate the capability again to
      // Carol later
      delegator: bobKey.id,
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
    const signer = aliceCapabilityAgent.getSigner();
    const signedCapabilityFromAlice = await _delegate({
      capabilityChain: [
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer,
      zcap,
      documentLoader
    });

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: carolKey.id,
      // the capability Alice gave to Bob
      parentCapability: zcap.id,
      // this is where we need to ensure the allowedAction here is included
      // in the allowedAction of the parentCapability, there is an issue in
      // zcapld for this.
      allowedAction: 'sign',
      invocationTarget: zcap.invocationTarget
    };

    // finish bobs delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
        signedCapabilityFromAlice
      ],
      signer: bobKey,
      zcap: carolZcap,
      documentLoader
    });

    // now remove `proof` from carol's zcap to create a validation error
    delete signedCapabilityFromBobToCarol.proof;

    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bobKey is the `delegator` in `signedCapabilityFromBobToCarol`,
        // so invoke using it to revoke carol's zcap
        invocationSigner: bobKey
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.data.type.should.equal('ValidationError');
    err.data.message.should.equal(
      'A validation error occured in the \'delegatedZcap\' validator.');
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

async function _signWithDelegatedKey({capability, doc, invokeKey}) {
  const {httpsAgent} = brHttpsAgent;
  const delegatedSigningKey = new AsymmetricKey({
    capability,
    invocationSigner: invokeKey,
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
  capabilityToRevoke, invocationSigner
}) {
  const {httpsAgent} = brHttpsAgent;
  const kmsClient = new KmsClient({httpsAgent});
  await kmsClient.revokeCapability({
    capabilityToRevoke,
    invocationSigner
  });
}

async function _setKeyId(key) {
  // the keyDescription is required to get publicKeyBase58
  const keyDescription = await key.getKeyDescription();
  // create public ID (did:key) for bob's key
  const fingerprint =
    (await Ed25519VerificationKey2020.from(keyDescription)).fingerprint();
  // invocationTarget.publicAlias = `did:key:${fingerprint}`;
  key.id = `did:key:${fingerprint}#${fingerprint}`;
}
