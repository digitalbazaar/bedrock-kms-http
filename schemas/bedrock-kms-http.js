/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const cidrRegex = require('cidr-regex');

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
          // was: verificationMethod
          publicAlias: {
            title: 'publicAlias',
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
        proofValue: {
          title: 'proofValue',
          type: 'string'
        },
      }},
    referenceId
  }
};

const ipAllowList = {
  type: 'array',
  minItems: 1,
  items: {
    type: 'string',
    // leading and trailing slashes in regex must be removed
    pattern: cidrRegex.v4({exact: true}).toString().slice(1, -1),
  }
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
  required: ['sequence', 'controller', 'meterCapability'],
  properties: {
    controller,
    ipAllowList,
    referenceId,
    sequence,
    meterCapability: zcap
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
    ipAllowList,
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
