/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {
  CapabilityAgent, KmsClient, KeystoreAgent
} from '@digitalbazaar/webkms-client';

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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // next, delegate authority to bob to use alice's key
    const rootCapability = ZCAP_ROOT_PREFIX +
      encodeURIComponent(aliceKeystoreAgent.keystoreId);
    const bobZcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: bobCapabilityAgent.id,
      invocationTarget: aliceKey.kmsId,
      allowedAction: 'sign',
      delegator: aliceCapabilityAgent
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await helpers.signWithDelegatedKey({
      capability: bobZcap,
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    bobSignedDocument.should.have.property('@context');
    bobSignedDocument.should.have.property('example:foo');
    bobSignedDocument.should.have.property('proof');
    bobSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    bobSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob has successfully used alice's key to sign a document!

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = await helpers.delegate({
      parentCapability: bobZcap,
      controller: carolCapabilityAgent.id,
      delegator: bobCapabilityAgent
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await helpers.signWithDelegatedKey({
      capability: carolZcap,
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('example:foo');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob now submits a revocation to revoke the capability he gave to Carol.

    // in practice bob is going to locate the capability he gave to carol
    // by way of bedrock-web-zcap-storage

    // this adds a revocation for Carol's `sign` capability on Alice's
    // kms system
    await helpers.revokeDelegatedCapability({
      // the `sign` capability that Bob gave to Carol
      capabilityToRevoke: carolZcap,
      // bob is doing the revocation
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await helpers.revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: carolZcap,
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
      result = await helpers.signWithDelegatedKey({
        capability: carolZcap,
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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // next, delegate authority to bob to use alice's key
    const rootCapability = ZCAP_ROOT_PREFIX +
      encodeURIComponent(aliceKeystoreAgent.keystoreId);
    const bobZcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: bobCapabilityAgent.id,
      invocationTarget: aliceKey.kmsId,
      allowedAction: 'sign',
      delegator: aliceCapabilityAgent
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await helpers.signWithDelegatedKey({
      capability: bobZcap,
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    bobSignedDocument.should.have.property('@context');
    bobSignedDocument.should.have.property('example:foo');
    bobSignedDocument.should.have.property('proof');
    bobSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    bobSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob has successfully used alice's key to sign a document!

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = await helpers.delegate({
      parentCapability: bobZcap,
      controller: carolCapabilityAgent.id,
      delegator: bobCapabilityAgent
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await helpers.signWithDelegatedKey({
      capability: carolZcap,
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('example:foo');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Carol now submits a revocation to revoke her own capability.

    // this adds a revocation for Carol's `sign` capability on Alice's
    // kms system
    await helpers.revokeDelegatedCapability({
      // the `sign` capability that Bob gave to Carol
      capabilityToRevoke: carolZcap,
      // carol is doing the revocation
      invocationSigner: carolCapabilityAgent.getSigner()
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await helpers.revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: carolZcap,
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
      result = await helpers.signWithDelegatedKey({
        capability: carolZcap,
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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // next, delegate authority to bob to use alice's key
    const rootCapability = ZCAP_ROOT_PREFIX +
      encodeURIComponent(aliceKeystoreAgent.keystoreId);
    const bobZcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: bobCapabilityAgent.id,
      invocationTarget: aliceKey.kmsId,
      allowedAction: 'sign',
      delegator: aliceCapabilityAgent
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await helpers.signWithDelegatedKey({
      capability: bobZcap,
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    bobSignedDocument.should.have.property('@context');
    bobSignedDocument.should.have.property('example:foo');
    bobSignedDocument.should.have.property('proof');
    bobSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    bobSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob has successfully used alice's key to sign a document!

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = await helpers.delegate({
      parentCapability: bobZcap,
      controller: carolCapabilityAgent.id,
      delegator: bobCapabilityAgent
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await helpers.signWithDelegatedKey({
      capability: carolZcap,
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('example:foo');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Diego now erroneously trys to revoke Carol's zcap
    let err;
    try {
      await helpers.revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: carolZcap,
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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // next, delegate authority to bob to use alice's key
    const rootCapability = ZCAP_ROOT_PREFIX +
      encodeURIComponent(aliceKeystoreAgent.keystoreId);
    const bobZcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: bobCapabilityAgent.id,
      invocationTarget: aliceKey.kmsId,
      allowedAction: 'sign',
      delegator: aliceCapabilityAgent
    });

    // Bob now uses his delegated authority to sign a document with Alice's key
    const bobSignedDocument = await helpers.signWithDelegatedKey({
      capability: bobZcap,
      invocationSigner: bobCapabilityAgent.getSigner()
    });

    bobSignedDocument.should.have.property('@context');
    bobSignedDocument.should.have.property('example:foo');
    bobSignedDocument.should.have.property('proof');
    bobSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    bobSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Bob has successfully used alice's key to sign a document!

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = await helpers.delegate({
      parentCapability: bobZcap,
      controller: carolCapabilityAgent.id,
      delegator: bobCapabilityAgent
    });

    // Bob would then store record of the delegation to Carol in an EDV

    // demonstrate that Carol can also sign with Alice's key
    const carolSignedDocument = await helpers.signWithDelegatedKey({
      capability: carolZcap,
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('example:foo');
    carolSignedDocument.should.have.property('proof');
    carolSignedDocument.proof.should.have.property('verificationMethod');
    // the document was ultimately signed with alice's key
    carolSignedDocument.proof.verificationMethod.should.equal(aliceKey.id);

    // Carol now delegates the use of Alice's key to Diego
    const diegoZcap = await helpers.delegate({
      parentCapability: carolZcap,
      controller: diegoCapabilityAgent.id,
      delegator: carolCapabilityAgent
    });

    // Carol now submits a revocation to revoke the capability she gave to
    // Diego.

    // in practice carol is going to locate the capability she gave to diego
    // by way of bedrock-web-zcap-storage

    // this adds a revocation for Diego's `sign` capability on Alice's
    // kms system
    await helpers.revokeDelegatedCapability({
      // the `sign` capability that Carol gave to Diego
      capabilityToRevoke: diegoZcap,
      // carol is doing the revocation
      invocationSigner: carolCapabilityAgent.getSigner()
    });

    // an attempt to revoke the capability again should produce an error
    // that a capability in the chain has already been revoked
    let err;
    try {
      await helpers.revokeDelegatedCapability({
        // the `sign` capability that Carol gave to Diego
        capabilityToRevoke: diegoZcap,
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
      result = await helpers.signWithDelegatedKey({
        capability: diegoZcap,
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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // next, delegate authority to bob to use alice's key
    const rootCapability = ZCAP_ROOT_PREFIX +
      encodeURIComponent(aliceKeystoreAgent.keystoreId);
    const bobZcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: bobCapabilityAgent.id,
      invocationTarget: aliceKey.kmsId,
      allowedAction: 'sign',
      delegator: aliceCapabilityAgent
    });

    // Alice now DOES NOT sign the capability delegation; Bob is NOT
    // allowed to `sign` with her key.
    // this is simulated by deleting the proof on bob's zcap
    delete bobZcap.proof;

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = await helpers.delegate({
      parentCapability: bobZcap,
      controller: carolCapabilityAgent.id,
      delegator: bobCapabilityAgent,
      purposeOptions: {
        // since `bobZcap` is intentionally not signed, we must disable local
        // validation to allow bad zcap to be created so it can be tested by
        // the verifier and manually specify the capability chain
        _skipLocalValidationForTesting: true,
        _capabilityChain: [
          bobZcap.parentCapability,
          bobZcap
        ]
      }
    });

    let err;
    try {
      await helpers.revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: carolZcap,
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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // next, delegate authority to bob to use alice's key
    const rootCapability = ZCAP_ROOT_PREFIX +
      encodeURIComponent(aliceKeystoreAgent.keystoreId);
    const bobZcap = await helpers.delegate({
      parentCapability: rootCapability,
      controller: bobCapabilityAgent.id,
      invocationTarget: aliceKey.kmsId,
      allowedAction: 'sign',
      delegator: aliceCapabilityAgent
    });

    // Bob now delegates the use of Alice's key to Carol
    const carolZcap = await helpers.delegate({
      parentCapability: bobZcap,
      controller: carolCapabilityAgent.id,
      delegator: bobCapabilityAgent
    });

    // now remove `proof` from carol's zcap to create a validation error
    delete carolZcap.proof;

    let err;
    try {
      await helpers.revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: carolZcap,
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
