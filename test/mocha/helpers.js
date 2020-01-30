/*
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brHttpsAgent = require('bedrock-https-agent');
const {KmsClient} = require('webkms-client');

// the `keystores` endpoint uses session based authentication which is
// mocked
exports.createKeystore = async ({controllerKey, referenceId}) => {
  // create keystore
  const config = {
    sequence: 0,
    controller: controllerKey.id,
    invoker: controllerKey.id,
    delegator: controllerKey.id
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
