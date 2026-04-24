/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {handlers} from '@bedrock/meter-http';
import '@bedrock/https-agent';
import '@bedrock/kms';
import '@bedrock/kms-http';
import '@bedrock/meter';
import '@bedrock/meter-usage-reporter';
import '@bedrock/mongodb';
import '@bedrock/security-context';
import '@bedrock/ssm-mongodb';

const {config} = bedrock;

bedrock.events.on('bedrock.configure', async () => {
  // use fresh test database
  config.mongodb.name = 'bedrock_kms_http_proxy_target_test';
  config.mongodb.dropCollections = {
    onInit: true,
    collections: []
  };

  // allow self-signed certs in test framework
  config['https-agent'].rejectUnauthorized = false;
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
