/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const forwarded = require('forwarded');
const {Netmask} = require('netmask');

exports.getKeystoreId = ({host, req, localId, routes}) => {
  if(!host) {
    host = req.get('host');
  }
  return `https://${host}${routes.keystores}/${localId}`;
};

exports.verifyRequestIp = ({keystoreConfig, req}) => {
  const {ipAllowList} = keystoreConfig;
  if(!ipAllowList) {
    return {verified: true};
  }

  // the first IP in the sourceAddresses array will *always* be the IP
  // reported by Express.js via `req.connection.remoteAddress`. Any additional
  // IPs will be from the `x-forwarded-for` header.
  const sourceAddresses = forwarded(req);

  // ipAllowList is an array of CIDRs
  for(const cidr of ipAllowList) {
    const netmask = new Netmask(cidr);
    for(const address of sourceAddresses) {
      if(netmask.contains(address)) {
        return {verified: true};
      }
    }
  }

  return {verified: false};
};
