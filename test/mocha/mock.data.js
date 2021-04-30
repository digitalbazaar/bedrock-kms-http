/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */

const {CONTEXT_URL: ZCAP_CONTEXT_URL, CONTEXT: ZCAP_CONTEXT} =
  require('zcap-context');
const {securityLoader} = require('@digitalbazaar/security-document-loader');

const loader = securityLoader();
loader.addStatic(ZCAP_CONTEXT_URL, ZCAP_CONTEXT);

const securityDocumentLoader = loader.build();

const data = {};

module.exports = data;

const zcaps = data.zcaps = {};
data.documentLoader = securityDocumentLoader;
const zcap0 = {
  '@context': ZCAP_CONTEXT_URL,
  id: 'urn:zcap:z19vWhR8EsNbWqvazp5bg6BTu',
  controller: 'did:key:z6Mkkt1BWYLPAAXwYBwyVHAZkL94tgT8QbQv2SUxeW1U3DaG',
  referenceId: 'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg#z6' +
    'MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg-key-capabilityInvocation',
  allowedAction: 'sign',
  invocationTarget: {
    id: 'https://bedrock.localhost:18443/kms/keystores/z1AAWWM7Zd4YyyV3NfaCq' +
      'FuzQ/keys/z19wxodgv1UhrToQMvSxGhQG6',
    type: 'Ed25519VerificationKey2020',
    publicAlias: 'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwT' +
      'TTYvg#z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg'
  },
  invoker: 'did:key:z6MkfV83MxASJKXim3eBPoLCDiWDseYUaW84qbVF9k3ngdfg#z6MkfV83' +
    'MxASJKXim3eBPoLCDiWDseYUaW84qbVF9k3ngdfg',
  parentCapability: 'https://bedrock.localhost:18443/kms/keystores/z1AAWWM7Zd' +
    '4YyyV3NfaCqFuzQ/keys/z19wxodgv1UhrToQMvSxGhQG6',
  proof: {
    type: 'Ed25519Signature2020',
    created: '2020-02-27T21:22:48Z',
    verificationMethod: 'did:key:z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwT' +
      'TTYvg#z6MkkrtV7wnBpXKBtiZjxaSghCo8ttb5kZUJTk8bEwTTTYvg',
    proofPurpose: 'capabilityDelegation',
    capabilityChain: [
      'https://bedrock.localhost:18443/kms/keystores/z1AAWWM7Zd4YyyV3NfaCqFu' +
        'zQ/keys/z19wxodgv1UhrToQMvSxGhQG6'
    ],
    // FIXME: This was a 'jws'; need to find actual proofValue for this zcap
    proofValue: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19'
  }
};

zcaps.zero = zcap0;
