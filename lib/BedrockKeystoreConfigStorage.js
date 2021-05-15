/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {KeystoreConfigStorage} = require('webkms-switch');
const {keystores} = require('bedrock-kms');
const bedrock = require('bedrock');
const {util: {BedrockError}} = bedrock;
const helpers = require('./helpers');

// load config defaults
require('./config');

module.exports = class BedrockKeystoreConfigStorage
  extends KeystoreConfigStorage {
  async get({id, req} = {}) {
    const {config: keystoreConfig} = await keystores.get({id});

    // verify that request is from an IP that is allowed to access the config
    const {verified} = helpers.verifyRequestIp({keystoreConfig, req});
    if(!verified) {
      throw new BedrockError(
        'Permission denied. Source IP is not allowed.', 'NotAllowedError', {
          httpStatusCode: 403,
          public: true,
        });
    }

    return keystoreConfig;
  }
};
