/*
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {validator: validate} = require('bedrock-kms-http/lib/validator');

describe('validator', () => {
  it('throws error if "bodySchema" or "querySchema" is not provided',
    async () => {
      let res;
      let err;
      try {
        res = await validate({});
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.message.should.equal(
        'One of the following parameters is required: ' +
        '"bodySchema", "querySchema".');
    });
});
