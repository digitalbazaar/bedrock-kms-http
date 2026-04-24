/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {handlers} from '@bedrock/meter-http';
import '@bedrock/express';
import '@bedrock/https-agent';
import '@bedrock/kms';
import '@bedrock/kms-http';
import '@bedrock/meter';
import '@bedrock/meter-usage-reporter';
import '@bedrock/mongodb';
import '@bedrock/security-context';
import '@bedrock/server';
import '@bedrock/ssm-mongodb';
import '@bedrock/zcap-storage';

const {config} = bedrock;

bedrock.events.on('bedrock.configure', async () => {
  // use fresh test database
  config.mongodb.name = 'bedrock_kms_http_test';
  config.mongodb.dropCollections = {
    onInit: true,
    collections: []
  };

  // allow self-signed certs in test framework
  config['https-agent'].rejectUnauthorized = false;

  // run on non-default port
  config.server.port = 22144;
  config.server.httpPort = 22180;
  config.server.domain = 'localhost';

  // external address
  config.server.host = 'localhost:18443';

  // enable to receive traffic over HTTP instead
  //config.express.httpOnly = true;

  // trust incoming proxy headers
  config.express.fastifyOptions.trustProxy = true;

  // disable zcap revocation cache so tests will pass without having to
  // wait for expiry
  config['zcap-storage'].caches.revocation.ttl = 1;
});

bedrock.events.on('bedrock.init', async () => {
  /* Handlers need to be added before `bedrock.start` is called. These are
  no-op handlers to enable meter usage without restriction */
  handlers.setCreateHandler({
    handler({meter} = {}) {
      // use configured meter usage reporter as service ID for tests
      meter.serviceId = config['app-identity'].seeds.services.webkms.id;
      return {meter};
    }
  });
  handlers.setUpdateHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setRemoveHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setUseHandler({handler: ({meter} = {}) => ({meter})});
});

bedrock.start();
