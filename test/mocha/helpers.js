/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent, KeystoreAgent, KmsClient} =
  require('@digitalbazaar/webkms-client');
const {httpsAgent} = require('bedrock-https-agent');
const brPassport = require('bedrock-passport');
const sinon = require('sinon');

// the `keystores` endpoint uses session based authentication which is
// mocked
exports.createKeystore = async ({
  capabilityAgent, ipAllowList, referenceId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`,
}) => {
  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
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
    httpsAgent,
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
    keystore,
    kmsClient
  });

  return keystoreAgent;
};

exports.getKeystore = async ({id}) => {
  return KmsClient.getKeystore({id, httpsAgent});
};

exports.findKeystore = async ({
  controller, referenceId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`
}) => {
  const url = `${kmsBaseUrl}/keystores` +
    `/?controller=${controller}&referenceId=${referenceId}`;
  return KmsClient.findKeystore({
    url, controller, referenceId, httpsAgent
  });
};

exports.enableCapability = async ({
  capabilityToEnable, capability, invocationSigner
}) => {
  return KmsClient.enableCapability({
    capabilityToEnable, capability, invocationSigner
  });
};

exports.stubPassport = ({actor}) => {
  const passportStub = sinon.stub(brPassport, 'optionallyAuthenticated');
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account: {},
      actor,
    };
    next();
  });
  return passportStub;
};
