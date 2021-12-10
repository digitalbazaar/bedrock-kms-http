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
  let carolCapabilityAgent;
  let diegoCapabilityAgent;

  before(async () => {
    const secret = '40762a17-1696-428f-a2b2-ddf9fe9b4987';
    const handle = 'alice';
    aliceCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    const {id: keystoreId} = await helpers.createKeystore(
      {capabilityAgent: aliceCapabilityAgent});
    const {httpsAgent} = brHttpsAgent;
    const kmsClient = new KmsClient({httpsAgent});
    aliceKeystoreAgent = new KeystoreAgent(
      {capabilityAgent: aliceCapabilityAgent, keystoreId, kmsClient});
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

  // generate a capability agent for Diego
  before(async () => {
    const secret = 'b9cec27e-59fd-11ec-9567-10bf48838a41';
    const handle = 'diego';
    diegoCapabilityAgent = await CapabilityAgent.fromSecret({secret, handle});
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
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer: aliceCapabilityAgent.getSigner(),
      zcap,
      documentLoader
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAliceToBob,
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
      controller: carolCapabilityAgent.id,
      parentCapability: signedCapabilityFromAliceToBob.id,
      allowedAction: 'sign',
      invocationTarget: signedCapabilityFromAliceToBob.invocationTarget,
    };

    // finish bob's delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
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
      invocationSigner: carolCapabilityAgent.getSigner()
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
      // bob is doing the revocation
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bob is doing the revocation
        invocationSigner: bobCapabilityAgent.getSigner()
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
        invocationSigner: carolCapabilityAgent.getSigner()
      });
    } catch(e) {
      err = e;
    }
    should.not.exist(result);
    should.exist(err);
    should.exist(err.data);
    err.data.type.should.equal('NotAllowedError');
  });
  it('successfully demonstrates self-revocation of a delegation', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(aliceKey);
    // next, delegate authority to bob to use alice's key
    const zcap = {
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
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer: aliceCapabilityAgent.getSigner(),
      zcap,
      documentLoader
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAliceToBob,
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
      controller: carolCapabilityAgent.id,
      parentCapability: signedCapabilityFromAliceToBob.id,
      allowedAction: 'sign',
      invocationTarget: signedCapabilityFromAliceToBob.invocationTarget,
    };

    // finish bob's delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
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
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('referenceId');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Carol now submits a revocation to revoke her own capability.

    // this adds a revocation for Carol's `sign` capability on Alice's
    // kms system
    await _revokeDelegatedCapability({
      // the `sign` capability that Bob gave to Carol
      capabilityToRevoke: signedCapabilityFromBobToCarol,
      // carol is doing the revocation
      invocationSigner: carolCapabilityAgent.getSigner()
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // carol is doing the revocation
        invocationSigner: carolCapabilityAgent.getSigner()
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.status.should.equal(403);
    should.exist(err.data);
    const {data} = err;
    data.type.should.equal('NotAllowedError');

    // demonstrate that Carol can no longer use Alice's key for signing.
    let result;
    err = null;
    try {
      result = await _signWithDelegatedKey({
        capability: signedCapabilityFromBobToCarol,
        invocationSigner: carolCapabilityAgent.getSigner()
      });
    } catch(e) {
      err = e;
    }
    should.not.exist(result);
    should.exist(err);
    should.exist(err.data);
    err.data.type.should.equal('NotAllowedError');
  });
  it('stops an unauthorized party from revoking a delegation', async () => {
    // first generate a new key for alice
    const aliceKey = await aliceKeystoreAgent.generateKey({type: 'asymmetric'});
    await _setKeyId(aliceKey);
    // next, delegate authority to bob to use alice's key
    const zcap = {
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
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer: aliceCapabilityAgent.getSigner(),
      zcap,
      documentLoader
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAliceToBob,
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
      controller: carolCapabilityAgent.id,
      parentCapability: signedCapabilityFromAliceToBob.id,
      allowedAction: 'sign',
      invocationTarget: signedCapabilityFromAliceToBob.invocationTarget,
    };

    // finish bob's delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
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
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('referenceId');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Diego now erroneously trys to revoke Carol's zcap
    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // diego is doing the revocation
        invocationSigner: diegoCapabilityAgent.getSigner()
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.status.should.equal(403);
    should.exist(err.data);
    const {data} = err;
    data.type.should.equal('NotAllowedError');
  });
  it('successfully revokes a delegation with a deeper chain', async () => {
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
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer: aliceCapabilityAgent.getSigner(),
      zcap: bobZcap,
      documentLoader
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await _signWithDelegatedKey({
      capability: signedCapabilityFromAliceToBob,
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
      invocationTarget: signedCapabilityFromAliceToBob.invocationTarget,
    };

    // finish bob's delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
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
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('referenceId');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Carol now delegates the use of Alice's key to Diego
    const diegoZcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Diego's zcap
      controller: diegoCapabilityAgent.id,
      parentCapability: signedCapabilityFromBobToCarol.id,
      allowedAction: 'sign',
      invocationTarget: signedCapabilityFromBobToCarol.invocationTarget,
    };

    // finish carol's delegation to diego
    const signedCapabilityFromCarolToDiego = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
        signedCapabilityFromAliceToBob.id,
        signedCapabilityFromBobToCarol
      ],
      signer: carolCapabilityAgent.getSigner(),
      zcap: diegoZcap,
      documentLoader
    });

    // Carol now submits a revocation to revoke the capability she gave to
    // Diego.

    // in practice carol is going to locate the capability she gave to diego
    // by way of bedrock-web-zcap-storage

    // this adds a revocation for Diego's `sign` capability on Alice's
    // kms system
    await _revokeDelegatedCapability({
      // the `sign` capability that Carol gave to Diego
      capabilityToRevoke: signedCapabilityFromCarolToDiego,
      // carol is doing the revocation
      invocationSigner: carolCapabilityAgent.getSigner()
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Carol gave to Diego
        capabilityToRevoke: signedCapabilityFromCarolToDiego,
        // carol is doing the revocation
        invocationSigner: carolCapabilityAgent.getSigner()
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.status.should.equal(403);
    should.exist(err.data);
    const {data} = err;
    data.type.should.equal('NotAllowedError');

    // Carol would then update her delegation record in an EDV to indicate that
    // the delegation is now revoked. This is just a housekeeping measure,
    // Diego's capability is revoked on Alice's system and is no longer valid.

    // demonstrate that Diego can no longer use Alice's key for signing.
    let result;
    err = null;
    try {
      result = await _signWithDelegatedKey({
        capability: signedCapabilityFromCarolToDiego,
        invocationSigner: diegoCapabilityAgent.getSigner()
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

    // Alice now DOES NOT sign the capability delegation; Bob is NOT
    // allowed to `sign` with her key.

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = {
      '@context': ZCAP_CONTEXT_URL,
      // this is a unique ID
      id: `urn:zcap:${uuid()}`,
      // this is Carol's zcap
      controller: carolCapabilityAgent.id,
      // the capability Alice gave to Bob (but we failed to sign it)
      parentCapability: bobZcap.id,
      allowedAction: 'sign',
      invocationTarget: bobZcap.invocationTarget
    };

    // finish bob's delegation to carol
    const signedCapabilityFromBobToCarol = await _delegate({
      capabilityChain: [
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
        // bob's zcap is erroneously unsigned
        bobZcap
      ],
      signer: bobCapabilityAgent.getSigner(),
      zcap: carolZcap,
      documentLoader
    });

    let err;
    try {
      await _revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: signedCapabilityFromBobToCarol,
        // bob is doing the revocation
        invocationSigner: bobCapabilityAgent.getSigner()
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
        // the root zcap for Alice's key is always the first
        // item in the `capabilityChain`
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId)
      ],
      signer: aliceCapabilityAgent.getSigner(),
      zcap: bobZcap,
      documentLoader
    });

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
        ZCAP_ROOT_PREFIX + encodeURIComponent(aliceKeystoreAgent.keystoreId),
        signedCapabilityFromAliceToBob
      ],
      signer: bobCapabilityAgent.getSigner(),
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
        // bob is doing the revocation
        invocationSigner: bobCapabilityAgent.getSigner()
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
