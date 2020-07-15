/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const controller = {
  title: 'controller',
  type: 'string'
};

const referenceId = {
  title: 'referenceId',
  type: 'string'
};

const postKeystore = {
  title: 'postKeystore',
  type: 'object',
  additionalProperties: false,
  required: ['sequence', 'controller'],
  properties: {
    controller,
    referenceId,
    sequence: {
      title: 'sequence',
      type: 'number',
      minimum: 0,
      maximum: Number.MAX_SAFE_INTEGER - 1
    }}
};

const findKeystore = {
  title: 'findKeystore',
  type: 'object',
  additionalProperties: false,
  required: ['controller', 'referenceId'],
  properties: {
    controller,
    referenceId
  }
};

const zcap = {
  title: 'zcap',
  type: 'object',
  additionalProperties: false,
  required: ['id', 'invoker', 'parentCapability', 'allowedAction',
    'invocationTarget'],
  properties: {
    id: {
      title: 'id',
      type: 'string'
    },
    allowedAction: {
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    caveat: {
      title: 'Caveat',
      type: 'object'
    },
    '@context': {
      title: '@context',
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    controller,
    delegator: {
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    invoker: {
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    invocationTarget: {
      title: 'Invocation Target',
      anyOf: [{
        type: 'string'
      }, {
        type: 'object',
        properties: {
          id: {
            title: 'Invocation Target Id',
            type: 'string'
          },
          type: {
            title: 'Invocation Target Type',
            type: 'string'
          }
        }
      }]
    },
    parentCapability: {
      title: 'Parent Capability',
      type: 'string'
    },
    proof: {
      title: 'Proof',
      type: 'object'
    },
    referenceId
  }
};

const recovery = {
  title: 'recovery',
  type: 'object',
  additionalProperties: false,
  required: ['@context', 'controller'],
  properties: {
    controller,
    '@context': {
      title: '@context', type: 'string'
    }}
};

module.exports = {
  findKeystore: () => findKeystore,
  postKeystore: () => postKeystore,
  zcap: () => zcap,
  recovery: () => recovery
};
