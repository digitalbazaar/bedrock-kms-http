# Bedrock Key Management System API module _(bedrock-kms-http)_
> HTTP APIs for Bedrock Key Management.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Install

- Node.js 12+ is required.

### NPM

To install via NPM:

```
npm install --save bedrock-kms-http
```

### Development

To install locally (for development):

```
git clone https://github.com/digitalbazaar/bedrock-kms-http.git
cd bedrock-kms-http
npm install
```

## Usage

In `lib/index.js` (or `main.js`, as appropriate):

```js
import 'bedrock-kms-http';
```

### KMS HTTP API

This module exposes the following API endpoints.

#### Create a Keystore - `POST /kms/keystores`

#### Request Example:
```
{
  sequence: 0,
  controller: 'did:key:z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54',
  meterId: 'https://localhost:18443/meters/z3pYurSyUQ5BTBcahRKuzri',
  kmsModule: 'ssm-v1'
}
```

#### Headers
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores",action="write"',
  digest: 'mh=uEiAWwH_YYtljJn-tba5XZ_s5k9lcFoJW9Mg8EdPY3ShEvQ',
  'content-type': 'application/json',
  authorization: 'Signature keyId="did:key:z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54#z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54",headers="(key-id) (created) (expires) (request-target) host capability-invocation content-type digest",signature="hTFuyAyfdwmTRJ1DmK2AVgDZ+RCQYsc5n9YF///5t4QY3VaTtUGWRDWQHRTSMGHybda782fCW9XczmIJEMfFDQ==",created="1638504433",expires="1638505033"'
}
```

#### Response Example:
```
{
  id: 'https://localhost:18443/kms/keystores/z1AByGXEmfZnyG8rgM3aVpYxG',
  meterId: 'https://localhost:18443/meters/z3pYurSyUQ5BTBcahRKuzri',
  sequence: 0,
  controller: 'did:key:z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54',
  kmsModule: 'ssm-v1'
}
```

#### Update Keystore Config - `POST /kms/keystores/:keystoreId`

#### Request Example:
```
{
  controller: 'did:key:z6MknP29cPcQ7G76MWmnsuEEdeFya8ij3fXvJcTJYLXadmp9',
  id: 'https://localhost:18443/kms/keystores/z19xPXyqB3dnqKZ7BtVFvqSLH',
  sequence: 1
}
```

#### Headers
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz19xPXyqB3dnqKZ7BtVFvqSLH",action="write"',
  digest: 'mh=uEiDiFdv-C0VNNIvltnoIxwqUA5crG1H42OyvQtPRa7mjvw',
  'content-type': 'application/json',
  authorization: 'Signature keyId="did:key:z6MkqnGN2jgckeejguN28RE1SM5a1rwu9nigkY5PhSQuTybX#z6MkqnGN2jgckeejguN28RE1SM5a1rwu9nigkY5PhSQuTybX",headers="(key-id) (created) (expires) (request-target) host capability-invocation content-type digest",signature="6i3yXShQMQ8H+XFJpUEi0WcO7hcrcpdApuyU2WrSAm0bMuAby+pZKSt+ACBWRrpocEaxAa6lwefvtGVYVXO7BQ==",created="1638505029",expires="1638505629"'
}
```

#### Response Example:
```
{
  success: true,
  config: {
    controller: 'did:key:z6MknP29cPcQ7G76MWmnsuEEdeFya8ij3fXvJcTJYLXadmp9',
    id: 'https://localhost:18443/kms/keystores/z19xPXyqB3dnqKZ7BtVFvqSLH',
    sequence: 1,
    meterId: 'https://localhost:18443/meters/zD3E9XJxyUUuJ5ZW14EhCFy',
    kmsModule: 'ssm-v1'
  }
}
```

#### Get Keystore Config - `GET /kms/keystores/:keystoreId`

#### Request Example:

#### Headers
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz1A2Dahs56An4rttS3t2QKi69",action="read"',
  authorization: 'Signature keyId="did:key:z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54#z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54",headers="(key-id) (created) (expires) (request-target) host capability-invocation",signature="P8ZYsAO/oQPllqRCW4GJdKwHhGfk53li88pzySd2jJVhNJCkxwPVNTGS0CsK/tK1cLvwjUABUqO2VUlP//T3DA==",created="1638505290",expires="1638505890"'
}
```

#### Response Example:
```
{
  id: 'https://localhost:18443/kms/keystores/z1A2Dahs56An4rttS3t2QKi69',
  meterId: 'https://localhost:18443/meters/zC3vXcEbC3iYEntNVZxvq6E',
  sequence: 0,
  controller: 'did:key:z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54',
  kmsModule: 'ssm-v1'
}
```

#### Generate a new Key - `POST /kms/keystores/:keystoreId/keys`

#### Request Example:
```
{
  '@context': [
    'https://w3id.org/webkms/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  type: 'GenerateKeyOperation',
  invocationTarget: { type: 'Ed25519VerificationKey2020' }
}
```

#### Headers:
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz19mH7zKauTKBWS3831MyWM2f",action="generateKey"',
  digest: 'mh=uEiC4fs8V2JzjgB25wxRhyKGc17b0yu-JvjnYF6IutYMEzQ',
  'content-type': 'application/json',
  authorization: 'Signature keyId="did:key:z6MkoSN3SbRHZAFdYwphhgHhuLXdBCMu7Yoam5H436b1PZAp#z6MkoSN3SbRHZAFdYwphhgHhuLXdBCMu7Yoam5H436b1PZAp",headers="(key-id) (created) (expires) (request-target) host capability-invocation content-type digest",signature="fntyQjEsGMIOwh7OftKS76yJ/1wpx+3eVWJjIToqcfJPOlmuU3DZmbag4bZ3cw3weLg4kDYQNxsJ8nNVtpd4DQ==",created="1638506601",expires="1638507201"'
}
```
#### Response Example:
```
{
  id: 'https://localhost:18443/kms/keystores/z19mH7zKauTKBWS3831MyWM2f/keys/z1A3XvbwPFZ5WceoeXcQMzBZ5',
  type: 'Ed25519VerificationKey2020',
  '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
  publicKeyMultibase: 'z6MknYsXcwi19ohJKGu5RHzxAkyVDGCP3ggpHY2FqxNFFyZb'
}
```

#### Invoke KMS Operation on Existing Key - `POST /kms/keystores/:keystoreId/keys/:keyId`

#### Request Example:
```
{
  '@context': 'https://w3id.org/webkms/v1',
  type: 'SignOperation',
  invocationTarget: 'https://localhost:18443/kms/keystores/z19zhh4xhWEeBn7u5NXQaeU2e/keys/z1A4nmgJS9XkDAsDDHFhAEba3',
  verifyData: 'aGVsbG8'
}
```

#### Headers
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz19zhh4xhWEeBn7u5NXQaeU2e",action="sign"',
  digest: 'mh=uEiADFF5OnUq5SCTrVVBSAMP5DpXfSF7f1bIH-SrX6S9Fdw',
  'content-type': 'application/json',
  authorization: 'Signature keyId="did:key:z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54#z6MkoyZVQSetDxU66AsfinUPzgSEu5N9Jf1anHEY4YCzcE54",headers="(key-id) (created) (expires) (request-target) host capability-invocation content-type digest",signature="upDUCqfbaIqixWmFjnHq/NIY2/r5TserYAQMOEkiwoUIyHgww/auN+cMYqH7x23cmymfmDIlDqqoE+Pi06j+AQ==",created="1638508033",expires="1638508633"'
}
```


#### Response Example:
```
{ signatureValue: 'qtL549jF562rlea6oQBzIKYCZeOPFX9OBzmn3iSzOpI' }
```

#### Get Public Key Description - `GET /kms/keystores/:keystoreId/keys/:keyId`

#### Request Example:

#### Headers
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz1AEdRUJm7Ld4xBNBKkAGHjzZ%2Fkeys%2Fz1A5vBtppSSaS1svFyQb6Ezwj",action="read"',
  authorization: 'Signature keyId="did:key:z6MkhRjrvpEAxh8oSWsPgMdP28xvrotsDBCvcwTtbUuUEp38#z6MkhRjrvpEAxh8oSWsPgMdP28xvrotsDBCvcwTtbUuUEp38",headers="(key-id) (created) (expires) (request-target) host capability-invocation",signature="gmB9DXTu29QKO4FlHXcEJGHMjaRpvXosRw+KeShiDB9YU2kwjMdd7eMT15TgeKzN3K5eqbEyEWh0NCgT/ULFAA==",created="1638539438",expires="1638540038"'
}
```

#### Response Example:
```
{
  '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
  id: 'https://localhost:18443/kms/keystores/z1AEdRUJm7Ld4xBNBKkAGHjzZ/keys/z1A5vBtppSSaS1svFyQb6Ezwj',
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: 'z6MkuP4PkTPZy2KvictPAsAHAbH6Umw9tsRJzmpGR65brddP'
}
```

#### Insert a Revocation - `POST /kms/keystores/:keystoreId/revocations/:zcapId`

#### Request Example:
```
{
  '@context': [
    'https://w3id.org/zcap/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  id: 'urn:zcap:38c42aff-76e0-4624-88dc-0341fe3f9ccd',
  invoker: 'did:key:z6MkootHWoSfwsPz1E3pE3aALJCEiawN1XNf4CPoUNeUEgY8#z6MkootHWoSfwsPz1E3pE3aALJCEiawN1XNf4CPoUNeUEgY8',
  parentCapability: 'urn:zcap:45bbf83c-bb97-474d-9a54-f4dac1e257ad',
  allowedAction: 'sign',
  invocationTarget: {
    publicAlias: 'did:key:z6Mkf8beJEDMQM77i12Siuw8UwuidEin6qvUQH65EBs3VqcW#z6Mkf8beJEDMQM77i12Siuw8UwuidEin6qvUQH65EBs3VqcW',
    id: 'https://localhost:18443/kms/keystores/z19zzGxGeo6Z4FhqhP1ZJZhNp/keys/z19qdYFKqymy8BoPpdfSkeRrZ',
    type: 'Ed25519VerificationKey2020'
  },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2021-12-03T00:54:36Z',
    verificationMethod: 'did:key:z6MkfrMHgiLotA5tX5JqtmQw1WmtmHCay7eY651TQzKdHAcB#z6MkfrMHgiLotA5tX5JqtmQw1WmtmHCay7eY651TQzKdHAcB',
    proofPurpose: 'capabilityDelegation',
    capabilityChain: [
      'urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz19zzGxGeo6Z4FhqhP1ZJZhNp',
      [Object]
    ],
    proofValue: 'z5UMPNnR2sXv5tZ4XVrRjGqwh6zPchrcNBgedXDS4XEnSgeQAFEuiAx89nUcxDZV2e2Tb17cZKoLvyvSdRorKHoHw'
  }
}
```

#### Headers
```
{
  accept: 'application/ld+json, application/json',
  host: 'localhost:18443',
  'capability-invocation': 'zcap id="urn:zcap:root:https%3A%2F%2Flocalhost%3A18443%2Fkms%2Fkeystores%2Fz1ADWeUn1vp2oTr33SaSoiiDj%2Frevocations%2Furn%253Azcap%253A61f9fce0-595d-4763-9854-c5db561e6981",action="write"',
  digest: 'mh=uEiCQYBu8dlESvD_MO4VxN3FcJMuSRg1HRh3B-ciaEHpsxQ',
  'content-type': 'application/json',
  authorization: 'Signature keyId="did:key:z6MkprpMfcYbjbCmhb84TWwhkwevqTX67EQvd7bdLTJ3DkA6#z6MkprpMfcYbjbCmhb84TWwhkwevqTX67EQvd7bdLTJ3DkA6",headers="(key-id) (created) (expires) (request-target) host capability-invocation content-type digest",signature="Z5DUpumlZYK3UplUDjz4szzWf+XO3zHd/Y6/wPMtUQn+7ZxNoLRa7Ny589CNASxYS7kg9Hv9KDF+R8wtiCJhAg==",created="1638492060",expires="1638492660"'
}
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[Bedrock Non-Commercial License v1.0](LICENSE.md) © Digital Bazaar
