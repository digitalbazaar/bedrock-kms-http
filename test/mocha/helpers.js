/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {KmsClient} = require('webkms-client');
const brPassport = require('bedrock-passport');
const sinon = require('sinon');

// the `keystores` endpoint uses session based authentication which is
// mocked
exports.createKeystore = async ({
  capabilityAgent, referenceId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`
}) => {
  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }

  const {httpsAgent} = brHttpsAgent;
  return KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    httpsAgent,
  });
};

exports.getKeystore = async ({id}) => {
  const {httpsAgent} = brHttpsAgent;
  return await KmsClient.getKeystore({id, httpsAgent});
};

exports.findKeystore = async ({
  controller, referenceId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`
}) => {
  const url = `${kmsBaseUrl}/keystores` +
  `/?controller=${controller}&referenceId=${referenceId}`;
  const {httpsAgent} = brHttpsAgent;
  return await KmsClient.findKeystore({
    url, controller, referenceId, httpsAgent
  });
};

exports.enableCapability = async ({
  capabilityToEnable, capability, invocationSigner
}) => {
  return await KmsClient.enableCapability({
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
