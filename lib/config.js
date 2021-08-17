/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
require('bedrock-validation');
require('bedrock-meter-usage-reporter');

const namespace = 'kms-http';
const cfg = config[namespace] = {};

const basePath = '/kms';
cfg.routes = {
  basePath
};

// storage size to report to meter service
cfg.storageCost = {
  revocation: 1
};

// create dev meter usage reporter client (must be overridden in deployments)
// ...and `ensureConfigOverride` has already been set via
// `bedrock-meter-usage-reporter` so it doesn't have to be set here
config['meter-usage-reporter'].clients.webkms = {
  id: 'did:key:z6MkfkHC4UqMtxbrbWF4Ctmz7ynCaKJvb8vD7TqaEbMSfsRF',
  keyPair: {
    id: 'did:key:z6MkfkHC4UqMtxbrbWF4Ctmz7ynCaKJvb8vD7TqaEbMSfsRF#' +
      'z6MkfkHC4UqMtxbrbWF4Ctmz7ynCaKJvb8vD7TqaEbMSfsRF',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z6MkfkHC4UqMtxbrbWF4Ctmz7ynCaKJvb8vD7TqaEbMSfsRF',
    privateKeyMultibase: 'zrv3edvEmYyXYikBkTMnNAHRSUc9veuDt7ku12JNTBKwrgd' +
      '67JfnjgDeD2TNgot3fUCdnUCbBzNq6GHbGBH8CZEt8a9'
  }
};
