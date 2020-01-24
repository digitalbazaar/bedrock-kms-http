/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const brZCapStorage = require('bedrock-zcap-storage');
const {config} = bedrock;
const cors = require('cors');
const helpers = require('./helpers');

bedrock.events.on('bedrock-express.configure.routes', app => {
  const cfg = config['kms-http'];
  const routes = {...cfg.routes};
  routes.keystores = `${routes.basePath}/keystores`;
  routes.revocations = `${routes.keystore}/revocations`;

  // insert an authorization
  app.options(routes.revocations, cors());
  app.post(
    routes.revocations,
    // CORs is safe because authorization uses HTTP signatures + capabilities,
    // not cookies
    cors(),
    // TODO: add zcap validator
    //validate('bedrock-kms-http.zcap'),
    asyncHandler(async (req, res) => {
      // check authorization
      const keystoreId = helpers.getKeystoreId(
        {req, localId: req.params.keystoreId, routes});
      const expectedTarget = `${keystoreId}/revocations`;
      const expectedRootCapability = `${keystoreId}/zcaps/revocations`;
      const {invoker} = await helpers.authorize({
        req, expectedTarget, expectedRootCapability,
        expectedAction: 'write'
      });

      // verify CapabilityDelegation before storing zcap
      const controller = invoker;
      const capability = req.body;
      const host = req.get('host');
      await helpers.verifyDelegation(
        {keystoreId, host, controller, capability});
      await brZCapStorage.revocations.insert({controller, capability});
      res.status(204).end();
    }));
});
