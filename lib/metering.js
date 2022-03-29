/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from 'bedrock';
import * as brZCapStorage from 'bedrock-zcap-storage';
import {
  defaultModuleManager as moduleManager,
  keystores
} from 'bedrock-kms';
import {meters} from 'bedrock-meter-usage-reporter';
import {logger} from './logger.js';

// configure usage aggregator for webkms meters
export const SERVICE_TYPE = 'webkms';
meters.setAggregator({serviceType: SERVICE_TYPE, handler: _aggregateUsage});

export function reportOperationUsage({req}) {
  // do not wait for usage to be reported
  const {keystore, keystore: {meterId: id}} = req.webkms;
  meters.use({id, operations: 1}).catch(
    error => logger.error(
      `Keystore (${keystore.id}) meter (${id}) usage error.`, {error}));
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
