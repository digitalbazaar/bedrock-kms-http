/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {decode} from 'base58-universal';
import {driver} from '@digitalbazaar/did-method-key';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {ZcapClient} from '@digitalbazaar/ezcap';

// found in bedrock-app-identity
const DEFAULT_APPLICATION_ID_SEED =
  'z1AmMXgweztXscpTpxx19jsCLkPXUacTTBme2oxWGvuto9S';

// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z';
// multihash identity function cdoe
const MULTIHASH_IDENTITY_FUNCTION_CODE = 0x00;
// seed byte size
const SEED_BYTE_SIZE = 32;

export async function createMeter({capabilityAgent} = {}) {
  const invocationSigner = await getInvocationSigner();
  const zcapClient = new ZcapClient({
    invocationSigner,
    SuiteClass: Ed25519Signature2020
  });

  // create a meter
  const meterService = 'https://localhost:18443/meters';
  let meter = {
    controller: capabilityAgent.id,
    product: {
      // mock ID for webkms service product
      id: 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
}

export async function getInvocationSigner() {
  // convert multibase seed to Uint8Array
  const seed = _decodeMultibaseSeed({
    seedMultibase: DEFAULT_APPLICATION_ID_SEED
  });

  const didKeyDriver = driver();
  const didKey = await didKeyDriver.generate({seed});

  const {didDocument: {capabilityInvocation}} = didKey;

  const capabilityInvocationKey = didKey.keyPairs.get(capabilityInvocation[0]);
  return capabilityInvocationKey.signer();
}

function _decodeMultibaseSeed({seedMultibase}) {
  const prefix = seedMultibase[0];
  if(prefix !== MULTIBASE_BASE58BTC_HEADER) {
    throw new Error('Unsupported multibase encoding.');
  }
  const data = seedMultibase.substring(1);
  // <varint hash fn code> <varint digest size in bytes> <hash fn output>
  //  <identity function>              <32>                <seed bytes>
  const seedMultihash = decode(data);
  // <varint hash fn code>: identity function
  const [hashFnCode] = seedMultihash.slice(0, 1);
  if(hashFnCode !== MULTIHASH_IDENTITY_FUNCTION_CODE) {
    throw new Error('Invalid multihash function code.');
  }
  // <varint digest size in bytes>: 32
  const [digestSize] = seedMultihash.slice(1, 2);
  if(digestSize !== SEED_BYTE_SIZE) {
    throw new Error('Invalid digest size.');
  }
  // <hash fn output>: seed bytes
  const seedBytes = seedMultihash.slice(2, seedMultihash.length);
  if(seedBytes.byteLength !== SEED_BYTE_SIZE) {
    throw new Error('Invalid digest.');
  }

  return seedBytes;
}
