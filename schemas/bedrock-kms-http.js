/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import cidrRegex from 'cidr-regex';

const controller = {
  title: 'controller',
  type: 'string'
};

const id = {
  title: 'id',
  type: 'string'
};

const delegatedZcap = {
  title: 'delegatedZcap',
  type: 'object',
  additionalProperties: false,
  required: [
    '@context', 'controller', 'expires', 'id', 'invocationTarget',
    'parentCapability', 'proof'
  ],
  properties: {
    controller,
    id,
    allowedAction: {
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    expires: {
      // FIXME: w3c datetime
      title: 'expires',
      type: 'string'
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
      type: 'string'
    },
    parentCapability: {
      title: 'Parent Capability',
      type: 'string'
    },
    proof: {
      title: 'Proof',
      type: 'object',
      additionalProperties: false,
      required: [
        'verificationMethod', 'type', 'created', 'proofPurpose',
        'capabilityChain', 'proofValue'
      ],
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
      }
    }
  }
};

const meterId = {
  title: 'Meter ID',
  type: 'string'
};

const ipAllowList = {
  type: 'array',
  minItems: 1,
  items: {
    type: 'string',
    // leading and trailing slashes in regex must be removed
    pattern: cidrRegex({exact: true}).toString().slice(1, -1),
  }
};

const sequence = {
  title: 'sequence',
  type: 'integer',
  minimum: 0,
  maximum: Number.MAX_SAFE_INTEGER - 1
};

const kmsModule = {
  title: 'kmsModule',
  type: 'string'
};

const postKeystoreBody = {
  title: 'postKeystoreBody',
  type: 'object',
  additionalProperties: false,
  required: ['sequence', 'controller', 'meterId'],
  properties: {
    controller,
    ipAllowList,
    sequence,
    kmsModule,
    meterId
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
    id,
    ipAllowList,
    sequence,
    kmsModule,
    meterId
  }
};

const postRevocationBody = {
  ...delegatedZcap
};

const getConfigsQuery = {
  title: 'Service Object Configuration Query',
  type: 'object',
  required: ['controller'],
  additionalProperties: false,
  properties: {
    controller
  }
};

export {
  getConfigsQuery,
  postKeystoreBody,
  postRevocationBody,
  updateKeystoreConfigBody
};
