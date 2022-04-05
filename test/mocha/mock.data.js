/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {createRequire} from 'module';
const require = createRequire(import.meta.url);
const {constants: zcapConstants} = require('@digitalbazaar/zcap');

const {ZCAP_CONTEXT_URL} = zcapConstants;

export const mockData = {};

const zcaps = mockData.zcaps = {};

// Note: This zcap is only used to check JSON schema validators, it does not
// have valid proofs.
const zcap0 = {
  '@context': ZCAP_CONTEXT_URL,
  id: 'urn:zcap:z19vWhR8EsNbWqvazp5bg6BTu',
  controller: 'did:key:z6Mkkt1BWYLPAAXwYBwyVHAZkL94tgT8QbQv2SUxeW1U3DaG',
  expires: '2022-01-08T17:27:15Z',
  invocationTarget: 'https://bedrock.localhost:18443/kms' +
    '/keystores/z1AAWWM7Zd4YyyV3NfaCqFuzQ/keys/z19wxodgv1UhrToQMvSxGhQG6',
  parentCapability: 'urn:zcap:root:' + encodeURIComponent(
    'https://bedrock.localhost:18443/kms/keystores/z1AAWWM7Zd4YyyV3NfaCqFuzQ'),
  allowedAction: 'sign',
  proof: {
    type: 'Ed25519Signature2020',
    created: '2020-02-27T21:22:48Z',
    verificationMethod: 'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwT' +
      'TTYvg#z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg',
    proofPurpose: 'capabilityDelegation',
    capabilityChain: [
      'urn:zcap:root:' + encodeURIComponent(
        'https://bedrock.localhost:18443/kms/keystores/z1AAWWM7Zd4YyyV3NfaCqFu')
    ],
    proofValue: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19'
  }
};

zcaps.zero = zcap0;
