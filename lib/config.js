/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from 'bedrock';
import 'bedrock-validation';
import 'bedrock-app-identity';
import 'bedrock-meter-usage-reporter';

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

// create dev application key for webkms (must be overridden in deployments)
// ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services.webkms = {
  id: 'did:key:z6MkwZ7AXrDpuVi5duY2qvVSx1tBkGmVnmRjDvvwzoVnAzC4',
  seedMultibase: 'z1AWrfBoQx1mbiWBfWT7eksbtJf91v2pvEpwhoHDzezfaiH',
  serviceType: 'webkms'
};

cfg.kmsOperationOptions = {
  maxChainLength: 10,
  // 300 second clock skew permitted by default
  maxClockSkew: 300,
  // 1000 year max TTL by default
  maxDelegationTtl: 1000 * 60 * 60 * 24 * 365 * 1000
};
