/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const operation = {
  title: 'KMS Operation',
  type: 'object',
  required: ['plugin', 'method'],
  additionalProperties: false,
  properties: {
    plugin: {
      type: 'string'
    },
    method: {
      type: 'string'
    },
    parameters: {
      type: 'object',
      additionalProperties: true
    }
  }
};

module.exports.postOperation = () => operation;
