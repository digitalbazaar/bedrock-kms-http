/*
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brHttpsAgent = require('bedrock-https-agent');
const helpers = require('./helpers');
const {CapabilityAgent, KmsClient, KeystoreAgent} =
  require('@digitalbazaar/webkms-client');

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
    // first generate a new key for alice; use a did:key ID for its public ID
    const aliceKey = await aliceKeystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#${publicKeyMultibase}'
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
      // bob signs the invocation to use alice's key (and alice's key will
      // sign the document)
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
      // carol signs the invocation to use alice's key (and alice's key
      // will sign the document)
      invocationSigner: carolCapabilityAgent.getSigner()
    });
    carolSignedDocument.should.have.property('@context');
    carolSignedDocument.should.have.property('example:foo');
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
      result = await helpers.revokeDelegatedCapability({
        // the `sign` capability that Bob gave to Carol
        capabilityToRevoke: carolZcap,
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
