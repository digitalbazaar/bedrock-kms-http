/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {
  defaultModuleManager: moduleManager,
  keystores
} = require('bedrock-kms');
const brZCapStorage = require('bedrock-zcap-storage');
const {meters} = require('bedrock-meter-usage-reporter');
const logger = require('./logger');

// configure usage aggregator for webkms meters
const SERVICE_TYPE = 'webkms';
exports.SERVICE_TYPE = SERVICE_TYPE;
meters.setAggregator({serviceType: SERVICE_TYPE, handler: _aggregateUsage});

exports.reportOperationUsage = async function({req}) {
  // do not wait for usage to be reported
  const {meterId: id} = req.webkms.keystore;
  meters.use({id, operations: 1}).catch(
    error => logger.error(`Meter (${id}) usage error.`, {error}));
};

exports.reportRevocationUsage = async function({meterId}) {
  await meters.use({id: meterId, operations: 1});
};

async function _aggregateUsage({meter, signal} = {}) {
  const {id: meterId} = meter;
  return keystores.getStorageUsage({
    meterId, moduleManager, aggregate: _addRevocationUsage, signal
  });
}

async function _addRevocationUsage({config, usage}) {
  // add storage units for revocations associated with the keystore
  const {id: keystoreId} = config;
  const {storageCost} = bedrock.config.kms;
  // if `count` is available, use it to count stored revocations
  if(brZCapStorage.revocations.count) {
    const {count} = await brZCapStorage.revocations.count(
      {rootTarget: keystoreId});
    usage.storage += count * storageCost.revocation;
  }
}
