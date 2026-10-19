/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import {config} from '@bedrock/core';
import '@bedrock/app-identity';
import '@bedrock/express';
import '@bedrock/meter-usage-reporter';
import '@bedrock/validation';

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

/* Optional proxy feature: An application running bedrock-kms-http can use
these configuration options to redirect KMS operations to another
bedrock-kms-http application, called a "proxy target". The proxy target must
shares the same database and be configured with the same public address
(domain / origin) but it is expected to be run behind a firewall (with
restricted access) and inside of an isolated environment, such as a secure
enclave, to add an additional layer of security during the processing of
KMS operations.

The proxying application will not have access to secret key material or to
secrets that can decrypt/unseal/unwrap other secrets, only the proxy target
will have access to some or all of these (or be capable of using some or all
of these via authz credentials only it can access). Both applications will
have access to the same database and will be expected to run compatible
versions of software to ensure database record compatibility. The proxy
target MUST properly check authz on all incoming requests; authz is is NOT
checked by the proxy.

Proxy entries are defined by KMS module, i.e., at most one proxy target can
be configured per KMS module. When requests for a particular KMS module arrive,
they are forwarded in their entirety to the related proxy target. */
cfg.kmsModuleProxy = {
  /*
  <kms-module-name>: {
    proxyTarget: <address (base URL) for kms proxy target>
  }
  */
};

// require raw JSON payloads for proxied routes to preserve specific content
// expression as it is used in signed digests
const createRawBodyParserOptions = () => ({
  raw: {
    type: ['json', '+json']
  }
});
const bodyParserRoutes = config.express.bodyParser.routes;
// for generating a new key
bodyParserRoutes['/kms/keystores/:keystoreId/keys'] =
  createRawBodyParserOptions();
// for running a key operation on an existing key
bodyParserRoutes['/kms/keystores/:keystoreId/keys/:keyId'] =
  createRawBodyParserOptions();
