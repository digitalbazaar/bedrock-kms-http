/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {httpsAgent} = require('bedrock-https-agent');
const {documentLoader} = require('bedrock-jsonld-document-loader');
const helpers = require('./helpers');
const jsigs = require('jsonld-signatures');
const {CapabilityDelegation} = require('ocapld');
const {AsymmetricKey, CapabilityAgent, KmsClient, KeystoreAgent} =
  require('webkms-client');
const {Ed25519KeyPair} = require('crypto-ld');
const {util: {uuid}} = bedrock;
const {
  purposes: {AssertionProofPurpose},
  sign,
  suites: {Ed25519Signature2018}
} = jsigs;

const KMS_MODULE = 'ssm-v1';

describe('revocations API', () => {
  let aliceCapabilityAgent;
  let aliceKeystoreAgent;
  let bobCapabilityAgent;
  let bobKeystoreAgent;
  let bobKey;
  let carolCapabilityAgent;
  let carolKey;
  let carolKeystoreAgent;

  let namespaceId;
  before(async () => {
    const result = await helpers.createNamespace();
    ({id: namespaceId} = result);
  });

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'testKey2';
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    const keystore = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent, namespaceId});
    const kmsClient = new KmsClient({httpsAgent});
    aliceKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: aliceCapabilityAgent, keystore, kmsClient});
  });

  // generate a keystore for Bob
  before(async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bobKey';
    bobCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
    const keystore = await helpers.createKeystore(
      {capabilityAgent: bobCapabilityAgent, namespaceId});
    try {
      const kmsClient = new KmsClient({httpsAgent});
      bobKeystoreAgent = new KeystoreAgent(
        {capabilityAgent: bobCapabilityAgent, keystore, kmsClient});
    } catch(e) {
      assertNoError(e);
    }
    try {
      bobKey = await bobKeystoreAgent.generateKey(
        {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});
    } catch(e) {
      assertNoError(e);
    }
    await _setKeyId(bobKey);
  });

  // generate a keystore for Carol
  before(async () => {
    const secret = 'ae806cd9-2765-4232-b955-01e1024ac032';
    const handle = 'carolKey';
    // keystore in the kmsClient is set later
    const kmsClient = new KmsClient({httpsAgent});
    carolCapabilityAgent = await CapabilityAgent.fromSecret({
      secret, handle, kmsClient
    });
    const keystore = await helpers.createKeystore(
      {capabilityAgent: carolCapabilityAgent, namespaceId});
    carolKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: carolCapabilityAgent, keystore, kmsClient});

    carolKey = await carolKeystoreAgent.generateKey(
      {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});
    await _setKeyId(carolKey);
  });

  // mock session authentication for delegations endpoint
  let passportStub;
  before(() => {
    const actor = {
      id: 'urn:uuid:7d1f8aea-5a22-480e-840b-d60bc5705864'
    };
    passportStub = helpers.stubPassport({actor});
  });
  after(() => {
    passportStub.restore();
  });

  it('successfully revokes a delegation', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey(
      {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});
    await _setKeyId(aliceKey);

    // next, delegate authority to bob to use alice's key
    const zcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Bob's capabilityInvocation key that will be used to invoke
      // the capability
      invoker: bobKey.id,
      // this provides Bob the ability to delegate the capability again to
      // Carol later
      delegator: bobKey.id,
      // if parentCapability points to a root capability it must be a
      // URL that can be dereferenced. In this case, aliceKey.kmsId is a root
      // capability.
      parentCapability: aliceKey.kmsId,
      allowedAction: 'sign',
      invocationTarget: {
        verificationMethod: aliceKey.id,
        id: aliceKey.kmsId,
        type: aliceKey.type,
      }
    };

    // This capability allows Bob to write to this revocations endpoint
    // This capability is required for Bob to revoke Carol's capability later.

    // the invoker for writing must be the delegator of the capability that is
    // being revoked there should also be a check that the invocation target
    // exists on the host system
    const bobRevocationZcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: bobKey.id,
      // there is no root capability at the `invocationTarget` location,
      // so this alternate URL is used that will automatically generate a
      // root capability
      parentCapability: `${aliceKeystoreAgent.keystore.id}/zcaps/revocations`,
      allowedAction: 'write',
      invocationTarget: `${aliceKeystoreAgent.keystore.id}/revocations`,
    };

    // Alice now signs the capability delegation that allows Bob to `sign`
    // with her key.
    const signer = aliceCapabilityAgent.getSigner();
    const signedCapabilityFromAlice = await _delegate({
      capabilityChain: [
        // Alice's key is the root capability which is always the first
        // item in the `capabilityChain`
        aliceKey.kmsId
      ],
      signer,
      zcap
    });

    // Alice now signs the capability delegation that allows Bob to `write`
    // to Alice's keystore revocations endpoint
    const signedBobRevocationZcap = await _delegate({
      capabilityChain: [bobRevocationZcap.parentCapability],
      signer,
      zcap: bobRevocationZcap
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAlice,
      invokeKey: bobKey,
    });

    bobSignedDocument.should.have.property('@context');
    bobSignedDocument.should.have.property('nonce');
    bobSignedDocument.should.have.property('proof');
    bobSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    bobSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob has successfully used alice's key to sign a document!

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: carolKey.id,
      // the capability Alice gave to Bob
      parentCapability: zcap.id,
      // this is where we need to ensure the allowedAction here is included
      // in the allowedAction of the parentCapability, there is an issue in
      // ocapld for this.
      allowedAction: 'sign',
      invocationTarget: zcap.invocationTarget,
    };

    // finish bobs delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        aliceKey.kmsId,
        zcap,
      ],
      signer: bobKey,
      zcap: carolZcap
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromBobToCarol,
      invokeKey: carolKey,
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('nonce');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob now submits a revocation using his revocation capability to
    // revoke the capability he gave to Carol.

    // in practice bob is going to locate the capability he gave to carol
    // by way of bedrock-web-zcap-storage

    // this adds a revocation for Carol's `sign` capability on Alice's
    // kms system
    await _revokeDelegatedCapability({
      // the capability here is to `write` to a revocations endpoint on
      // Alice's system
      capability: signedBobRevocationZcap,
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
        // the capability here is to `write` to a revocations endpoint on
        // Alice's system
        capability: signedBobRevocationZcap,
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bobKey is the `invoker` in `signedBobRevocationZcap`
        invocationSigner: bobKey
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.status.should.equal(400);
    should.exist(err.data);
    const {data} = err;
    data.message.should.include('capability delegation is invalid');
    data.type.should.equal('DataError');
    // TODO: with jsigs@5, err.cause should have additional details for assert

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
  it('throws error on zcaps validator', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey(
      {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});
    await _setKeyId(aliceKey);

    // next, delegate authority to bob to use alice's key
    const zcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Bob's capabilityInvocation key that will be used to invoke
      // the capability
      invoker: bobKey.id,
      // this provides Bob the ability to delegate the capability again to
      // Carol later
      delegator: bobKey.id,
      // if parentCapability points to a root capability it must be a
      // URL that can be dereferenced. In this case, aliceKey.kmsId is a root
      // capability.
      parentCapability: aliceKey.kmsId,
      allowedAction: 'sign',
      invocationTarget: {
        verificationMethod: aliceKey.id,
        id: aliceKey.kmsId,
        type: aliceKey.type,
      }
    };

    // This capability allows Bob to write to this revocations endpoint
    // This capability is required for Bob to revoke Carol's capability later.

    // the invoker for writing must be the delegator of the capability that is
    // being revoked there should also be a check that the invocation target
    // exists on the host system
    const bobRevocationZcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: bobKey.id,
      // there is no root capability at the `invocationTarget` location,
      // so this alternate URL is used that will automatically generate a
      // root capability
      parentCapability: `${aliceKeystoreAgent.keystore.id}/zcaps/revocations`,
      allowedAction: 'write',
      invocationTarget: `${aliceKeystoreAgent.keystore.id}/revocations`,
    };

    // Alice now signs the capability delegation that allows Bob to `sign`
    // with her key.
    const signer = aliceCapabilityAgent.getSigner();

    // Alice now signs the capability delegation that allows Bob to `write`
    // to Alice's keystore revocations endpoint
    const signedBobRevocationZcap = await _delegate({
      capabilityChain: [bobRevocationZcap.parentCapability],
      signer,
      zcap: bobRevocationZcap
    });

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: carolKey.id,
      // the capability Alice gave to Bob
      parentCapability: zcap.id,
      // this is where we need to ensure the allowedAction here is included
      // in the allowedAction of the parentCapability, there is an issue in
      // ocapld for this.
      allowedAction: 'sign'
    };

    // finish bobs delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        aliceKey.kmsId,
        zcap,
      ],
      signer: bobKey,
      zcap: carolZcap
    });

    let err;
    try {
      await _revokeDelegatedCapability({
        // the capability here is to `write` to a revocations endpoint on
        // Alice's system
        capability: signedBobRevocationZcap,
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bobKey is the `invoker` in `signedBobRevocationZcap`
        invocationSigner: bobKey
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.data.message.should.equal(
      'A validation error occured in the \'zcap\' validator.');
  });
});

async function _delegate({zcap, signer, capabilityChain}) {
  // attach capability delegation proof
  return sign(zcap, {
    // TODO: map `signer.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityDelegation({capabilityChain}),
    compactProof: false
  });
}

async function _signWithDelegatedKey({capability, doc, invokeKey}) {
  const delegatedSigningKey = new AsymmetricKey({
    capability,
    invocationSigner: invokeKey,
    kmsClient: new KmsClient({httpsAgent})
  });
  const suite = new Ed25519Signature2018({
    verificationMethod: capability.invocationTarget.verificationMethod,
    signer: delegatedSigningKey
  });

  doc = doc || {
    '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
    // just using a term out of security context
    nonce: 'bar'
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
  const kmsClient = new KmsClient({httpsAgent});
  await kmsClient.revokeCapability({
    capabilityToRevoke,
    capability,
    invocationSigner
  });
}

async function _setKeyId(key) {
  // the keyDescription is required to get publicKeyBase58
  const keyDescription = await key.getKeyDescription();
  // create public ID (did:key) for bob's key
  // TODO: do not use did:key but support a did:v1 based key.
  const fingerprint = Ed25519KeyPair.fingerprintFromPublicKey(keyDescription);
  // invocationTarget.verificationMethod = `did:key:${fingerprint}`;
  key.id = `did:key:${fingerprint}#${fingerprint}`;
}
