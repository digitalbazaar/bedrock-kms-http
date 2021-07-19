/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {CapabilityAgent, KeystoreAgent, KmsClient} =
  require('@digitalbazaar/webkms-client');
const {httpClient} = require('@digitalbazaar/http-client');
const {httpsAgent} = require('bedrock-https-agent');

exports.createMeter = async ({controller} = {}) => {
  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller,
    product: {
      // ID for webkms service
      id: 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'
    }
  };
  const response = await httpClient.post(meterService, {
    agent: httpsAgent, json: meter
  });
  ({data: {meter}} = response);

  // return usage capability
  const {usageCapability: meterCapability} = meter;
  return {meterCapability};
};

exports.createKeystore = async ({
  capabilityAgent, ipAllowList, referenceId, meterCapability,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`,
  kmsModule = 'ssm-v1',
}) => {
  if(!meterCapability) {
    // create a meter for the keystore
    ({meterCapability} = await exports.createMeter(
      {controller: capabilityAgent.id}));
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterCapability,
    kmsModule
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
    httpsAgent
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
    keystoreId: keystore.id,
    kmsClient
  });

  return keystoreAgent;
};

exports.getKeystore = async ({id, capabilityAgent}) => {
  const kmsClient = new KmsClient({keystoreId: id, httpsAgent});
  const invocationSigner = capabilityAgent.getSigner();
  return kmsClient.getKeystore({invocationSigner});
};

// FIXME: consider removal
/*exports.findKeystore = async ({
  controller, referenceId,
  kmsBaseUrl = `${bedrock.config.server.baseUri}/kms`
}) => {
  const url = `${kmsBaseUrl}/keystores` +
    `/?controller=${controller}&referenceId=${referenceId}`;
  return KmsClient.findKeystore({
    url, controller, referenceId, httpsAgent
  });
};
*/
