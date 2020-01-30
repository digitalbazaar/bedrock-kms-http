/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {documentLoader} = require('bedrock-jsonld-document-loader');
const helpers = require('./helpers');
const jsigs = require('jsonld-signatures');
const {CapabilityDelegation} = require('ocapld');
const {CapabilityAgent, KmsClient, KeystoreAgent} =
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

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'testKey2';
    const {httpsAgent} = brHttpsAgent;
    // keystore in the kmsClient is set later
    const kmsClient = new KmsClient({httpsAgent});
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({
      secret, handle, kmsClient
    });

    const keystore = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent});
    aliceKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: aliceCapabilityAgent, keystore, kmsClient});
  });

  // generate a keystore for Bob
  before(async () => {
    const secret = '34f2afd1-34ef-4d46-a998-cdc5462dc0d2';
    const handle = 'bobKey';
    const {httpsAgent} = brHttpsAgent;
    // keystore in the kmsClient is set later
    const kmsClient = new KmsClient({httpsAgent});
    bobCapabilityAgent = await CapabilityAgent.fromSecret({
      secret, handle, kmsClient
    });
    const keystore = await helpers.createKeystore(
      {capabilityAgent: bobCapabilityAgent});
    bobKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: bobCapabilityAgent, keystore, kmsClient});

    bobKey = await bobKeystoreAgent.generateKey(
      {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});

    // the keyDescription is required to get publicKeyBase58
    const keyDescription = await bobKey.getKeyDescription();

    // create public ID (did:key) for bob's key
    // TODO: do not use did:key but support a did:v1 based key.
    const fingerprint = Ed25519KeyPair.fingerprintFromPublicKey(keyDescription);
    // invocationTarget.verificationMethod = `did:key:${fingerprint}`;
    bobKey.id = `did:key:${fingerprint}#${fingerprint}`;
  });

  // generate a keystore for Carol
  before(async () => {
    const secret = 'ae806cd9-2765-4232-b955-01e1024ac032';
    const handle = 'carolKey';
    const {httpsAgent} = brHttpsAgent;
    // keystore in the kmsClient is set later
    const kmsClient = new KmsClient({httpsAgent});
    carolCapabilityAgent = await CapabilityAgent.fromSecret({
      secret, handle, kmsClient
    });
    const keystore = await helpers.createKeystore(
      {capabilityAgent: carolCapabilityAgent});
    carolKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: carolCapabilityAgent, keystore, kmsClient});

    carolKey = await carolKeystoreAgent.generateKey(
      {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});

    // the keyDescription is required to get publicKeyBase58
    const keyDescription = await carolKey.getKeyDescription();

    // create public ID (did:key) for carol's key
    // TODO: do not use did:key but support a did:v1 based key.
    const fingerprint = Ed25519KeyPair.fingerprintFromPublicKey(keyDescription);
    // invocationTarget.verificationMethod = `did:key:${fingerprint}`;
    carolKey.id = `did:key:${fingerprint}#${fingerprint}`;
  });

  it('does something', async () => {

    // first generate a new key
    const aliceKey = await aliceKeystoreAgent.generateKey(
      {type: 'Ed25519VerificationKey2018', kmsModule: KMS_MODULE});

    // next, delegate authority to use the key
    const zcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this should be a capabilityInvocation key that will be used to
      // invoke the revocation capability
      invoker: bobKey.id,
      delegator: bobKey.id,
      // the root capability is the key
      parentCapability: aliceKey.id,
      allowedAction: 'sign',
      invocationTarget: {
        verificationMethod: aliceKey.id,
        id: aliceKey.kmsId,
        type: aliceKey.type,
      }
    };

    // this capability allows bob to write to this endpoint
    // anyone who writes to the revocation collection, the invoker for writing
    // must be the delegator of the capability that is being revoked
    // there should also be a check that the invocation target exists on
    // the host system
    const bobRevocationZcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      invoker: bobKey.id,
      parentCapability: `${aliceKeystoreAgent.keystore}/zcaps/revocations`,
      allowedAction: 'write',
      invocationTarget: `${aliceKeystoreAgent.keystore}/revocations`,
    };

    // const targetType = 'urn:webkms:revocations';
    // zcap.invocationTarget = {
    //   id: key.id,
    //   type: targetType
    // };

    // const keystore = controllerKey.kmsClient.keystore;

    // zcap.parentCapability = `${keystore}/zcaps/revocations`;

    const signer = aliceCapabilityAgent.getSigner();
    const signedCapabilityFromAlice = await _delegate({zcap, signer});

    // create an interface to use the issuer's key via the capability
    const {httpsAgent} = brHttpsAgent;
    // keystore in the kmsClient is set later
    const kmsClient = new KmsClient({httpsAgent});
    const aKeystoreAgent = new KeystoreAgent({
      capabilityAgent: bobCapabilityAgent,
      kmsClient,
    });

    const delegatedSigningKey = await aKeystoreAgent.getAsymmetricKey({
      capability: signedCapabilityFromAlice
    });

    const suite = new Ed25519Signature2018({
      verificationMethod: delegatedSigningKey.id,
      signer: delegatedSigningKey
    });

    const signedDocument = await sign({
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // just using something out of security context
      nonce: 'bar'
    }, {
      documentLoader,
      suite,
      purpose: new AssertionProofPurpose(),
    });

    // bob has successfully used alice's key to sign a document!

    const carolZcap = {
      '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this should be a capabilityInvocation key that will be used to
      // invoke the revocation capability
      // NOTE: this specifies the exact key, however it could also be
      // did:key:bobskeyfingerprint without the hash fragment
      invoker: carolKey.id,
      // the capability alice gave bob
      parentCapability: zcap.id,
      // this is where we need to ensure the allowedAction here is included
      // in the allowedAction of the parentCapability, there is an issue in
      // ocapld for this.
      allowedAction: 'sign',
      invocationTarget: zcap.invocationTarget,
    };

    // finish bobs delegation to carol

    // bob uses bedrock-web-zcap-storage to store the delegation to carol

    // demonstrate that carol can also sign with alices key
    // bob should then submit a revocation using his revocation capability to
    // revoke the capability he gave to carol.

    // in practice bob is going to locate the capability he gave to carol
    // by way of bedrock-web-zcap-storage

    // using the keystoreAgent setup for alice
    // this API is currently on master of webkms-client
    // this adds a revocation on alice's kms system
    await aKeystoreAgent.kmsClient.revokeCapability({
      capabilityToRevoke: carolZcap,
      capabilty: bobRevocationZcap,
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    // bob uses bedrock-web-zcap-storage to indicate the capability stored
    // in the delegations collection is now revoked. This is just a
    // housekeeping measure, carols capability is revoked on alice's system
    // and is no longer valid

    // demonstrate that carol can no longer use alice's key for signing.
  });
});

async function _delegate({zcap, signer}) {
  // attach capability delegation proof
  return sign(zcap, {
    // TODO: map `signer.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityDelegation({
      // TODO: if this is not the root capability, then the capability may need
      // to be embedded here.

      // FIXME: this will need to support a longer chain
      capabilityChain: [zcap.parentCapability]
    }),
    compactProof: false
  });
}
