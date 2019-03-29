/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const context = {
  type: 'string',
  enum: ['https://w3id.org/security/v2']
};

const proof = {
  type: 'object',
  required: [
    'type', 'capability', 'created', 'jws',
    'proofPurpose', 'verificationMethod'
  ],
  additionalProperties: false,
  properties: {
    type: {
      type: 'string'
    },
    created: {
      type: 'string'
    },
    capability: {
      type: 'string'
    },
    capabilityAction: {
      type: 'string'
    },
    proofPurpose: {
      type: 'string',
      enum: ['capabilityInvocation']
    },
    verificationMethod: {
      type: 'string'
    },
    jws: {
      type: 'string'
    }
  }
};

const ExportKeyOperation = {
  required: ['@context', 'proof', 'type'],
  additionalProperties: false,
  properties: {
    '@context': context,
    proof,
    type: {
      type: 'string',
      enum: ['ExportKeyOperation']
    }
  }
};

const GenerateKeyOperation = {
  required: ['@context', 'proof', 'type', 'invocationTarget'],
  additionalProperties: false,
  properties: {
    '@context': context,
    proof,
    type: {
      type: 'string',
      enum: ['GenerateKeyOperation']
    },
    invocationTarget: {
      type: 'object',
      required: ['id', 'type', 'controller'],
      properties: {
        id: {
          type: 'string'
        },
        type: {
          type: 'string'
        },
        controller: {
          type: 'string'
        }
      }
    }
  }
};

const SignOperation = {
  required: ['@context', 'proof', 'type', 'verifyData'],
  additionalProperties: false,
  properties: {
    '@context': context,
    proof,
    type: {
      type: 'string',
      enum: ['SignOperation']
    },
    verifyData: {
      type: 'string'
    }
  }
};

const UnwrapKeyOperation = {
  required: ['@context', 'proof', 'type', 'wrappedKey'],
  additionalProperties: false,
  properties: {
    type: {
      type: 'string',
      enum: ['UnwrapKeyOperation']
    },
    wrappedKey: {
      type: 'string'
    }
  }
};

const VerifyOperation = {
  required: ['@context', 'proof', 'type', 'signatureValue', 'verifyData'],
  additionalProperties: false,
  properties: {
    '@context': context,
    proof,
    type: {
      type: 'string',
      enum: ['VerifyOperation']
    },
    signatureValue: {
      type: 'string'
    },
    verifyData: {
      type: 'string'
    }
  }
};

const WrapKeyOperation = {
  required: ['@context', 'proof', 'type', 'wrappedKey'],
  additionalProperties: false,
  properties: {
    '@context': context,
    proof,
    type: {
      type: 'string',
      enum: ['WrapKeyOperation']
    },
    wrappedKey: {
      type: 'string'
    }
  }
};

const operation = {
  title: 'KMS Operation',
  type: 'object',
  anyOf: [
    ExportKeyOperation,
    GenerateKeyOperation,
    SignOperation,
    UnwrapKeyOperation,
    VerifyOperation,
    WrapKeyOperation
  ]
};

module.exports.postOperation = () => operation;
