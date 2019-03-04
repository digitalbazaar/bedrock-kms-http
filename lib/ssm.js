/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const assert = require('assert-plus');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const uuid = require('uuid-random');
const {BedrockError} = bedrock.util;

// load config defaults
require('./config');

const AES_KW_ALGORITHM = 'id-aes256-wrap';
const AES_KW_RFC3394_IV = new Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

// module API
const api = {};
module.exports = api;

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['ssm']);

  await promisify(database.createIndexes)([{
    // cover queries by ID
    collection: 'ssm',
    fields: {id: 1},
    options: {unique: true, background: false}
  }, {
    // cover queries by controller
    collection: 'ssm',
    fields: {controller: 1},
    options: {unique: false, background: false}
  }]);
});

/**
 * Generates a new key.
 *
 * @param {String} controller the ID of the controller of the key.
 * @param {String} type the type of key (e.g. 'AES-KW', 'HS256').
 *
 * @return {Promise<Object>} resolves to `{id}`.
 */
api.generateKey = async ({controller, type}) => {
  assert.string(controller, 'controller');
  assert.string(type, 'type');

  let key;
  const id = uuid();

  if(type === 'AES-KW') {
    // TODO: support other lengths?
    key = {
      algorithm: 'AES-KW',
      secret: base64url.encode(crypto.randomBytes(32))
    };
  } else if(type === 'HS256') {
    // TODO: support other hashes?
    key = {
      algorithm: 'HS256',
      secret: base64url.encode(crypto.randomBytes(32))
    };
  } else {
    throw new Error(`Unknown key type "${type}".`);
  }

  // insert the key and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  const record = {
    id: database.hash(id),
    controller: database.hash(controller),
    meta,
    key
  };
  try {
    await database.collections.ssm.insert(record, database.writeOptions);
    return {id};
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate key identifier.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
};

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {String} controller the ID of the controller of the key.
 * @param {String} kekId the ID of the KEK.
 * @param {String} key the base64url-encoded cryptographic key to wrap.
 *
 * @return {Promise<Object>} resolves to `{wrappedKey}`.
 */
api.wrapKey = async ({controller, kekId, key}) => {
  assert.string(controller, 'controller');
  assert.string(kekId, 'kekId');
  assert.string(key, 'key');

  const {key: kek} = await _getKeyRecord({id: kekId, controller});
  if(kek.algorithm !== 'AES-KW') {
    throw new Error(`Unknown unwrapping algorithm "${kek.algorithm}".`);
  }

  const wrappedKey = await _aesWrapKey({kek, key});
  return {wrappedKey};
};

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {String} controller the ID of the controller of the key.
 * @param {String} kekId the ID of the KEK.
 * @param {String} wrappedKey the base64url-encoded cryptographic key to unwrap.
 *
 * @return {Promise<Object>} resolves to `{key}`.
 */
api.unwrapKey = async ({controller, kekId, wrappedKey}) => {
  assert.string(controller, 'controller');
  assert.string(kekId, 'kekId');
  assert.string(wrappedKey, 'wrappedKey');

  const {key: kek} = await _getKeyRecord({id: kekId, controller});
  if(kek.algorithm !== 'AES-KW') {
    throw new Error(`Unknown unwrapping algorithm "${kek.algorithm}".`);
  }

  const key = await _aesUnwrapKey({kek, wrappedKey});
  return {key};
};

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {String} controller the ID of the controller of the key.
 * @param {String} keyId the ID of the signing key to use.
 * @param {Uint8Array|String} data the data to sign as a Uint8Array
 *   or a base64url-encoded string.
 *
 * @return {Promise<Object>} resolves to `{signature}`.
 */
api.sign = async ({controller, keyId, data}) => {
  assert.string(controller, 'controller');
  assert.string(keyId, 'keyId');
  assert.string(data, 'data');

  const {key} = await _getKeyRecord({id: keyId, controller});

  const signature = await _hs256Sign({key, data});
  return {signature: base64url.encode(signature)};
};

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {String} controller the ID of the controller of the key.
 * @param {String} keyId the ID of the signing key to use.
 * @param {Uint8Array|String} data the data to sign as a Uint8Array
 *   or a base64url-encoded string.
 * @param {String} signature the base64url-encoded signature to verify.
 *
 * @return {Promise<Object>} resolves to `{verified}`.
 */
api.verify = async ({controller, keyId, data, signature}) => {
  assert.string(controller, 'controller');
  assert.string(keyId, 'keyId');
  assert.string(data, 'data');
  assert.string(signature, 'signature');

  const {key} = await _getKeyRecord({id: keyId, controller});

  const verified = await _hs256Verify({key, data, signature});
  return {verified};
};

/**
 * Gets a previously stored key record.
 *
 * @param {String} controller the controller of the key.
 * @param {String} id the ID of the key.
 *
 * @return {Promise<Object>} resolves to the key record.
 */
async function _getKeyRecord({controller, id}) {
  assert.string(controller, 'controller');
  assert.string(id, 'id');

  const record = await database.collections.ssm.findOne(
    {controller: database.hash(controller), id: database.hash(id)},
    {_id: 0, key: 1, meta: 1});
  if(!record) {
    throw new BedrockError(
      'Key not found.',
      'NotFoundError',
      {key: id, controller, httpStatusCode: 404, public: true});
  }

  return record;
}

async function _aesWrapKey({kek, key}) {
  key = base64url.decode(key);
  const secret = base64url.decode(kek.secret);
  const cipher = crypto.createCipheriv(
    AES_KW_ALGORITHM, secret, AES_KW_RFC3394_IV);
  const output = Buffer.concat([cipher.update(key), cipher.final()]);
  return base64url.encode(output);
}

async function _aesUnwrapKey({kek, wrappedKey}) {
  wrappedKey = base64url.decode(wrappedKey);
  const secret = base64url.decode(kek.secret);
  const decipher = crypto.createDecipheriv(
    AES_KW_ALGORITHM, secret, AES_KW_RFC3394_IV);
  const output = Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
  return base64url.encode(output);
}

async function _hs256Sign({key, data}) {
  const secret = base64url.decode(key.secret);
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(base64url.decode(data));
  return hmac.digest();
}

async function _hs256Verify({key, data, signature}) {
  signature = base64url.decode(signature);
  const signatureCheck = _hs256Verify({key, data});
  return crypto.timingSafeEqual(signature, signatureCheck);
}
