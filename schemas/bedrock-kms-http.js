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

const delegator = {
  anyOf: [{
    type: 'string'
  }, {
    type: 'array',
    minItems: 1,
    items: {type: 'string'}
  }]
};

const invoker = {
  anyOf: [{
    type: 'string'
  }, {
    type: 'array',
    minItems: 1,
    items: {type: 'string'}
  }]
};

const sequence = {
  title: 'sequence',
  type: 'integer',
  minimum: 0,
  maximum: Number.MAX_SAFE_INTEGER - 1
};

const postKeystoreBody = {
  title: 'postKeystoreBody',
  type: 'object',
  additionalProperties: false,
  required: ['sequence', 'controller'],
  properties: {
    controller,
    referenceId,
    sequence,
  }
};

const getKeystoreQuery = {
  title: 'getKeystoreQuery',
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
  required: [
    'id', 'invoker', 'parentCapability', 'allowedAction', 'invocationTarget'
  ],
  properties: {
    controller,
    invoker,
    delegator,
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
    invocationTarget: {
      title: 'Invocation Target',
      anyOf: [{
        type: 'string'
      }, {
        type: 'object',
        required: [
          'type', 'id'
        ],
        additionalProperties: false,
        properties: {
          id: {
            title: 'Invocation Target Id',
            type: 'string'
          },
          type: {
            title: 'Invocation Target Type',
            type: 'string'
          },
          controller: {
            title: 'controller',
            type: 'string'
          },
          verificationMethod: {
            title: 'verificationMethod',
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
      type: 'object',
      additionalProperties: false,
      properties: {
        verificationMethod: {
          title: 'verificationMethod',
          type: 'string'
        },
        type: {
          title: 'type',
          type: 'string'
        },
        created: {
          title: 'created',
          type: 'string'
        },
        proofPurpose: {
          title: 'proofPurpose',
          type: 'string'
        },
        capabilityChain: {
          title: 'capabilityChain',
          type: 'array',
          minItems: 1,
          items: {
            type: ['string', 'object']
          }
        },
        jws: {
          title: 'jws',
          type: 'string'
        },
      }},
    referenceId
  }
};

const updateKeystoreConfigBody = {
  title: 'updateKeystoreConfigBody',
  type: 'object',
  additionalProperties: false,
  required: [
    'controller',
    'id',
    'sequence',
  ],
  properties: {
    controller,
    id: {type: 'string'},
    referenceId,
    sequence,
  }
};

module.exports = {
  getKeystoreQuery,
  postKeystoreBody,
  zcap,
  updateKeystoreConfigBody
};
