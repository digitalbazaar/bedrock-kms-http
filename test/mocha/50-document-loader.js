/*!
 * Copyright (c) 2021-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {documentLoader} from '@bedrock/kms-http/lib/documentLoader.js';

describe('documentLoader', () => {
  it('returns a did document from the document loader', async () => {
    const url = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';

    let err;
    let result;
    try {
      result = await documentLoader(url);
    } catch(e) {
      err = e;
    }

    should.exist(result);
    should.not.exist(err);
    result.should.have.keys(['contextUrl', 'documentUrl', 'document']);
    result.documentUrl.should.equal(url);
  });

  it('throws NotFoundError on document not found', async () => {
    const url = 'https://example.com/foo.jsonld';

    let err;
    let result;
    try {
      result = await documentLoader(url);
    } catch(e) {
      err = e;
    }

    should.not.exist(result);
    should.exist(err);
    err.should.be.instanceOf(Error);
    err.message.should.contain(url);
  });
});
