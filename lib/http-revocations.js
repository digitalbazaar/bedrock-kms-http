/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brZCapStorage = require('bedrock-zcap-storage');
const {config, util: {BedrockError}} = bedrock;
const cors = require('cors');
const helpers = require('./helpers');
const {validate} = require('bedrock-validation');

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];
  const routes = {...cfg.routes};
  routes.keystores = `${routes.basePath}/keystores`;
  routes.keystore = `${routes.keystores}/:keystoreId`;
  routes.revocations = `${routes.keystore}/revocations`;

  // insert a revocation
  app.options(routes.revocations, cors());
  app.post(
    routes.revocations,
    // CORs is safe because revocation uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    validate('bedrock-kms-http.zcap'),
    asyncHandler(async (req, res) => {
      // check revocation
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
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
