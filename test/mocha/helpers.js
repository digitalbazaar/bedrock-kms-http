/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {KmsClient} = require('webkms-client');
const {DelegationService} = require('bedrock-web-zcap-storage');
const brPassport = require('bedrock-passport');
const sinon = require('sinon');

// the `keystores` endpoint uses session based authentication which is
// mocked
exports.createKeystore = async ({capabilityAgent, referenceId}) => {
  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    invoker: capabilityAgent.id,
    delegator: capabilityAgent.id
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }
  const kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`;
  const {httpsAgent} = brHttpsAgent;
  return await KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    httpsAgent,
  });
};

exports.storeDelegation = async ({delegation}) => {
  const {httpsAgent} = brHttpsAgent;
  const ds = new DelegationService({
    baseURL: `${bedrock.config.server.baseUri}`,
    httpsAgent,
  });
  await ds.create(delegation);
};

exports.deleteDelegation = async ({id}) => {
  const {httpsAgent} = brHttpsAgent;
  const ds = new DelegationService({
    baseURL: `${bedrock.config.server.baseUri}`,
    httpsAgent,
  });
  await ds.delete({id});
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
