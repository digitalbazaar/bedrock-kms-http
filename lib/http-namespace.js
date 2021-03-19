/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {express} = require('bedrock-express');

const {config} = bedrock;

bedrock.events.on('bedrock-express.configure.routes', () => {
  const router = express.Router();

  // remove the leading slash from the route
  const appKey = config['kms-http'].routes.basePath.substr(1);
  config.namespace.applications[appKey] = router;

  bedrock.events.emit('bedrock-kms-http.configure.routes', router);
});
