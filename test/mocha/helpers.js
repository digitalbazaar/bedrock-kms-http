/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent, KeystoreAgent, KmsClient} = require('webkms-client');
const {agent, httpsAgent} = require('bedrock-https-agent');
const brPassport = require('bedrock-passport');
const {httpClient} = require('@digitalbazaar/http-client');
const sinon = require('sinon');

const {config} = bedrock;

// the `keystores` endpoint uses session based authentication which is
// mocked
exports.createKeystore = async ({
  capabilityAgent, ipAllowList, namespaceId, referenceId
}) => {
  // create keystore
  const keystoreConfig = {
    sequence: 0,
    controller: capabilityAgent.id,
  };
  if(referenceId) {
    keystoreConfig.referenceId = referenceId;
  }
  if(ipAllowList) {
    keystoreConfig.ipAllowList = ipAllowList;
  }
  const keystoresUrl = `${namespaceId}${config['kms-http'].routes.basePath}` +
    `${config['kms-http'].routes.keystores}`;
  return KmsClient.createKeystore({
    url: keystoresUrl,
    config: keystoreConfig,
    httpsAgent,
  });
};

exports.createKeystoreAgent = async ({
  handle, ipAllowList, secret, kmsClientHeaders = {}
}) => {
  const capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

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

exports.createNamespace = async () => {
  const nsBaseUrl = `${bedrock.config.server.baseUri}/ns`;
  const controller = 'urn:uuid:a2a530e9-788b-4e7d-ad5e-865bc4078ef8';
  const zcap = {
    id: 'urn:uuid:011d784b-19ba-4a80-9cb3-bb1c2749148c',
  };
  const namespaceConfig = {
    controller,
    sequence: 0,
    zcap,
  };
  const result = await httpClient.post(nsBaseUrl, {
    agent,
    json: namespaceConfig,
  });

  return result.data;
};

exports.getKeystore = async ({id}) => {
  return KmsClient.getKeystore({id, httpsAgent});
};

exports.findKeystore = async ({
  controller, namespaceId, referenceId,
}) => {
  const url = `${namespaceId}/kms/keystores` +
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
