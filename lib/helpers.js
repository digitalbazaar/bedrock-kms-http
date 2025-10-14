/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import forwarded from 'forwarded';
import ipaddr from 'ipaddr.js';

const {config} = bedrock;

export function getKeystoreId({host, req, localId, routes}) {
  if(!host) {
    host = config.server.host || req.get('host');
  }
  return `https://${host}${routes.keystores}/${localId}`;
}

export function verifyRequestIp({keystoreConfig, req}) {
  // skip check if no IP allow list configured
  const {ipAllowList} = keystoreConfig;
  if(!ipAllowList) {
    return {verified: true};
  }

  // the first IP in the sourceAddresses array will *always* be the IP
  // reported by Express.js via `req.connection.remoteAddress`. Any additional
  // IPs will be from the `x-forwarded-for` header.
  const sourceAddresses = forwarded(req);

  // build list of allowed IP ranges from IPv4/IPv6 CIDRs
  const ipAllowRangeList = {
    allow: ipAllowList.map(cidr => ipaddr.parseCIDR(cidr))
  };

  // check if any source address allowed
  const verified = sourceAddresses.some(address => {
    const ip = ipaddr.parse(address);
    // check if in allow list, else deny
    return ipaddr.subnetMatch(ip, ipAllowRangeList, 'deny') === 'allow';
  });

  return {verified};
}
