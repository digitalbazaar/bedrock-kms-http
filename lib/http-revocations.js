/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brZCapStorage = require('bedrock-zcap-storage');
const {config, util: {BedrockError}} = bedrock;
const cors = require('cors');
const helpers = require('./helpers');
const {keystores} = require('bedrock-kms');
const {validator: validate} = require('./validator');
const {zcap: zcapSchema} = require('../schemas/bedrock-kms-http');

bedrock.events.on('bedrock-kms-http.configure.routes', app => {
  const cfg = config['kms-http'];
  const routes = {...cfg.routes};
  routes.keystores = `/keystores`;
  routes.keystore = `${routes.keystores}/:keystoreId`;
  routes.revocations = `${routes.keystore}/revocations`;

  // insert a revocation
  app.options(routes.revocations, cors());
  app.post(
    routes.revocations,
    // CORs is safe because revocation uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    validate({bodySchema: zcapSchema}),
    asyncHandler(async (req, res) => {
      // check revocation
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});

      const {config: keystoreConfig} = await keystores.get({id: keystoreId});
      const {verified} = helpers.verifyRequestIp({keystoreConfig, req});
      if(!verified) {
        throw new BedrockError(
          'Permission denied. Source IP is not allowed.', 'NotAllowedError', {
            httpStatusCode: 403,
            public: true,
          });
      }

      const expectedTarget = `${keystoreId}/revocations`;
      const expectedRootCapability = `${keystoreId}/zcaps/revocations`;
      const {invoker} = await helpers.authorize({
        req, expectedTarget, expectedRootCapability,
        expectedAction: 'write'
      });

      // verify CapabilityDelegation before storing zcap
      const capability = req.body;
      const host = req.get('host');

      let delegator;
      try {
        const results = await helpers.verifyDelegation(
          {keystoreId, host, capability});
        ({delegator} = results[0].purposeResult);
        delegator = typeof _delegator === 'string' ? delegator : delegator.id;
      } catch(e) {
        throw new BedrockError(
          'The provided capability delegation is invalid.',
          'DataError', {
            httpStatusCode: 400,
            public: true,
            message: e.message
          }, e);
      }
      // ensure that the invoker of the write capability is the delegator
      // of the capability to be revoked
      if(delegator !== invoker) {
        throw new BedrockError('Permission denied.', 'NotAllowedError');
      }
      await brZCapStorage.revocations.insert({delegator, capability});
      res.status(204).end();
    }));
});
