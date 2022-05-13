/*
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {createRequire} from 'node:module';
import {keystores} from '@bedrock/kms';
const require = createRequire(import.meta.url);
const {KeystoreConfigStorage} = require('@digitalbazaar/webkms-switch');

const {util: {BedrockError}} = bedrock;

// load config defaults
import './config.js';

export class BedrockKeystoreConfigStorage extends KeystoreConfigStorage {
  async get({id, req, returnRecord = false, fresh = false} = {}) {
    const record = await keystores.get({id, fresh});
    const {config: keystoreConfig} = record;

    // skip request checks if specifically requested
    if(req === false) {
      return returnRecord ? record : keystoreConfig;
    }

    // verify that request is from an IP that is allowed to access the config
    const {verified} = helpers.verifyRequestIp({keystoreConfig, req});
    if(!verified) {
      throw new BedrockError(
        'Permission denied. Source IP is not allowed.', 'NotAllowedError', {
          httpStatusCode: 403,
          public: true,
        });
    }

    return returnRecord ? record : keystoreConfig;
  }
}
