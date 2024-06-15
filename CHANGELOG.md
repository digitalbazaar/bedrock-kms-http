# bedrock-kms-http ChangeLog

## 20.1.0 - 2024-mm-dd

### Changed
- Use `@digitalbazaar/ed25519-multikey` to resolve ed25519 verification methods.
  No changes to deployments are expected.

## 20.0.0 - 2024-04-14

### Changed
- **BREAKING**: Use peer dependency `@bedrock/kms@15` which does not include
  a `defaultDocumentLoader`. Instead, that document loader (that matches the
  previous implementation from `@bedrock/kms`) is provided in this module. No
  special changes to deployments to support this should be necessary. To
  reimplement the document loader feature, the following peer dependencies have
  been added (and which were removed from `@bedrock/kms`):
  - `@bedrock/did-context@5`
  - `@bedrock/did-io@10`
  - `@bedrock/jsonld-document-loader@4`
  - `@bedrock/security-context@8`
  - `@bedrock/veres-one-context@15`

## 19.0.0 - 2024-01-25

### Changed
- **BREAKING**: Make the use of the WebKMS context in WebKMS operations
  optional. No other changes should be needed to deployments that choose
  to update to this version, it is marked as a breaking change out of
  caution around potential test suites that were looking for errors to
  be thrown if the WebKMS context was not present. This will no longer
  be the case -- though if WebKMS operations are sent with the context
  present, those operations will still be accepted.

## 18.0.0 - 2023-09-20

### Changed
- Use `@digitalbazaar/ed25519-signature-2020@5`.
- Use `cidr-regex@4`. This version is pure ESM.
- **BREAKING**: Update peer deps:
  - Use `@bedrock/kms@14`. This version requires Node.js 18+.
  - Use `@bedrock/meter-usage-reporter@9`. This version requires Node.js 18+.
- Update test deps.

## 17.0.0 - 2023-08-09

### Changed
- **BREAKING**: Drop support for Node.js v16.
- Use `@bedrock/kms@13`.

## 16.0.0 - 2022-12-06

### Changed
- **BREAKING**: Use `@bedrock/kms@12` which does not create indexes for
  `referenceId`.

### Removed
- **BREAKING**: Remove support for setting a `referenceId` in the keystore
  config. This feature is not used and querying using it has not been supported
  for some time. Now passing it in a keystore config will generate a validation
  error.

## 15.0.0 - 2022-06-30

### Changed
- **BREAKING**: Require Node.js >=16.
- Use `package.json` `files` field.
- Update dependencies.
- **BREAKING**: Update peer dependencies.
  - `@bedrock/app-identity@4`
  - `@bedrock/kms@11`
  - `@bedrock/meter-usage-reporter@8`
  - `@bedrock/zcap-storage@8`
- Lint module.

### Added
- Support IPv6 CIDRs in `ipAllowList`.
  - Switching from `netmask` to `ipaddr.js` to support IPv6.

## 14.5.0 - 2022-06-19

### Changed
- Use `@bedrock/kms@10.3`.
- Use `@digitalbazaar/webkms-switch@10.3`.

## 14.4.0 - 2022-05-19

### Added
- Add max age header for CORS, defaulting to the max acceptable time for
  modern browsers of 86400 seconds (24 hours).

## 14.3.1 - 2022-05-16

### Fixed
- Use `@digitalbazaar/webkms-switch@10.2` to ensure that pre-cached `webkms`
  request meta data is not overwritten and that a custom `getRootController`
  function is used (to enable cache busting on KMS operations).

## 14.3.0 - 2022-05-16

### Added
- Add debug logging for keystore config cache busting.

## 14.2.1 - 2022-05-13

### Fixed
- Fix cache busting for invoked delegated zcap cases.

## 14.2.0 - 2022-05-13

### Changed
- Be more resilient to keystore config controller changes. When a keystore
  is new and KMS operations are performed on it that could cause false-positive
  fail authz errors, fetch a fresh version of the config to ensure that the
  controller has not changed.

## 14.1.0 - 2022-05-12

### Added
- Include full error as non-public `cause` in `onError` handler.

## 14.0.0 - 2022-04-29

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/core@6`
  - `@bedrock/app-identity@3`
  - `@bedrock/express@8`
  - `@bedrock/kms@10`
  - `@bedrock/meter-usage-reporter@7`
  - `@bedrock/validation@7`
  - `@bedrock/zcap-storage@7`.

## 13.0.0 - 2022-04-05

### Changed
- **BREAKING**: Rename package to `@bedrock/kms-http`.
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Remove default export.
- **BREAKING**: Require node 14.x.

## 12.1.0 - 2022-03-29

### Changed
- Update peer deps:
  - `bedrock@4.5`
  - `bedrock-express@6.4.1`
  - `bedrock-kms@8.3.0`
  - `bedrock-validation@5.6.3`
  - `bedrock-zcap-storage@5.2`.
- Update internals to use esm style and use `esm.js` to
  transpile to CommonJS.

### Removed
- Remove unused peer deps:
  - `bedrock-server`
  - `bedrock-jsonld-document-loader`
  - `bedrock-mongodb`.

## 12.0.1 - 2022-03-03

### Fixed
- Use `@digitalbazaar/webkms-switch@10` to be consistent with
  `@digitalbazaar/ezcap-express@6` and other breaking changes
  in this major version.

## 12.0.0 - 2022-03-01

### Changed
- **BREAKING**: Move zcap revocations to `/zcaps/revocations` to better
  future proof.
- **BREAKING**: Use `@digitalbazaar/ezcap-express@6`.
- **BREAKING**: This version is compatible with
  `@digitalbazaar/webkms-client@10`.

## 11.3.1 - 2022-02-12

### Changed
- Improve internal implementation of JSON schema validators.

## 11.3.0 - 2022-02-10

### Changed
- Use `bedrock-validation@5.4` with better schema compilation.

## 11.2.0 - 2022-02-08

### Added
- Allow KMS operations to be configured via config system and
  set defaults to allow long-lived zcaps.

## 11.1.1 - 2022-01-20

### Fixed
- Do not expose details from errors that aren't marked public.

## 11.1.0 - 2022-01-14

### Added
- Use webkms-switch@9.1 to enable passing `zcapInvocation` to KMS
  modules. This enables KMS modules to disallow key operations based
  on zcap invocation information, if desired.

## 11.0.0 - 2022-01-11

### Changed
- **BREAKING**: Use ezcap-express@5 and webkms-switch@9. These changes
  include major breaking simplifications to ZCAP (zcap@7).

## 10.2.0 - 2021-12-11

### Added
- Add tests and update `README.md`.

### Changed
- Require ezcap-express 4.3.x.

## 10.1.3 - 2021-12-10

### Fixed
- Combined duplicate error code paths to simplify; the relevant code ensures
  that when a client sends a keystore config with an ID that does not match
  the config ID in the request URL, an exception will be thrown.

## 10.1.2 - 2021-12-09

### Fixed
- Load keystore config for a particular request only once to create more
  consistent behavior. Multiple retrievals of the same keystore config during
  the lifetime of a request may result in loading different configs without
  this patch. This patch makes behavior more consistent by reusing the same
  loaded keystore config for the entire request. Note that there is a change
  to an assertion in a test on a returned error, however, that error was
  not going to be consistent in previous versions regardless. This fix makes
  it more consistent.

## 10.1.1 - 2021-11-24

### Fixed
- Fix bug in meter usage aggregation.

## 10.1.0 - 2021-11-23

### Added
- Do not allow zcap revocations to be stored if the meter associated with
  a keystore has been disabled. Storage of zcap revocations is permitted if
  there is no available storage to prevent potential security issues, however,
  the meter MUST not be disabled to make use of this feature. Very robust
  rate limiting MUST be applied to the revocation submission endpoint in
  a deployment to avoid significant storage overflow.

## 10.0.0 - 2021-10-07

### Changed
- **BREAKING**: Use `webkms-switch@8` which changes the way key IDs are
  generated. See the [changelog](https://github.com/digitalbazaar/webkms-switch/blob/main/CHANGELOG.md).

## 9.0.0 - 2021-09-02

### Changed
- **BREAKING**: Use bedrock-meter-usage-reporter@4. This new version now
  requires bedrock-app-identity to configure the identity for webkms
  applications.

## 8.0.1 - 2021-09-01

### Fixed
- Do not allow meter ID to be changed when updating keystore config as
  the keystore controller has insufficient authority to do so. This
  may be enabled in the future by requiring the root zcap controller
  to be the meter controller when changing the meter ID.

## 8.0.0 - 2021-08-31

### Changed
- **BREAKING**: Use bedrock-meter-usage-reporter@3. This new version simplifies
  meter usage zcap management by eliminating the need for a delegated zcap
  to allow reporting meter usage. Instead, the KMS service is the root
  controller for the meter usage endpoint for any meter that is specifically
  created and coupled to it.
- **BREAKING**: Creating a keystore now requires sending only the full URL
  `meterId` for a meter, not a meter capability. The meter will be presumed
  to be coupled to the KMS service -- and this will be confirmed via a call
  to retrieve the meter information.

## 7.1.0 - 2021-08-26

### Changed
- Use ezcap-express@4.2 to provide zcap revocation authorization implementation.
  Remove dependencies that are no longer needed because of this upgrade.

## 7.0.1 - 2021-08-18

### Fixed
- Ensure promise settles before returning key description.

## 7.0.0 - 2021-08-17

### Changed
- **BREAKING**: Updated to work with bedrock-meter-usage-reporter 2.x. This
  new version enables applications to bundle the webkms service with other
  services instead of requiring a microservices deployment architecture.

## 6.1.0 - 2021-07-23

### Changed
- Update peer dependencies; use bedrock-did-io@4.

## 6.0.0 - 2021-07-22

### Added
- **BREAKING** - Add storage and operation metering support. A meter capability
  must be provided to create a new keystore. This capability will be used to
  report keystore storage and operation usage to the associated meter.

### Changed
- **BREAKING**: Require `expires` to be set on delegated zcaps.
- **BREAKING**: Use updated bedrock-kms.
- **BREAKING**: Simplify zcap revocation model. Now any party that has been delegated a zcap can
  send it to a revocation address: `<keystoreId>/revocations/<zcap ID>` without needing to have an
  additional zcap delegated to that party. The party must invoke the root zcap for that endpoint,
  which will be dynamically generated and use the delegator of the zcap as the controller, i.e., the
  delegator must invoke this root zcap to revoke the zcap they delegated.

### Removed
- **BREAKING**: Remove `did-io`, `did-method-key`, and
  `did-veres-one` from deps and use `bedrock-did-io`.
- **BREAKING**: Remove query endpoint. It was unused and a new design would need to
  be introduced in the future that properly handles authz.

## 5.0.0 - 2021-05-20

### Changed
- **BREAKING**: Remove `ed25519-signature-2018` signature suite and use
  `ed25519-signature-2020`.
- Remove `did-io`, `did-method-key`, and `did-veres-one` from deps and use
  `bedrock-did-io`.
- Update peerDeps and deps
  - [@digitalbazaar/ed25519-signature-2020@2.1.0](https://github.com/digitalbazaar/ed25519-signature-2020/blob/main/CHANGELOG.md)
  - [@digitalbazaar/ezcap-express@3.0.1](https://github.com/digitalbazaar/ezcap-express/blob/main/CHANGELOG.md)
  - [@digitalbazaar/zcapld@4.0.0](https://github.com/digitalbazaar/zcapld/blob/main/CHANGELOG.md)
  - [http-signature-zcap-verify@7.1.0](https://github.com/digitalbazaar/http-signature-zcap-verify/blob/main/CHANGELOG.md)
  - [jsonld-signatures@9.0.2](https://github.com/digitalbazaar/jsonld-signatures/blob/master/CHANGELOG.md)
  - [webkms-switch@5.0.0](https://github.com/digitalbazaar/webkms-switch/blob/main/CHANGELOG.md)
  - [bedrock-kms@6.0.0](https://github.com/digitalbazaar/bedrock-kms/blob/master/CHANGELOG.md)
  - [bedrock-did-io@2.0.0](https://github.com/digitalbazaar/bedrock-did-io/blob/main/CHANGELOG.md)
- Update test deps

### Added
- Keystore configurations may now include an optional `ipAllowList` array. If
  specified, the KMS system will only execute requests originating from IPs
  listed in `ipAllowList`. This applies to key operations for all keys in the
  keystore as well as modification of the configuration itself.

## 4.0.0 - 2021-03-02

### Added
- **BREAKING**: Implement ZCAP authz on the keystore config update API.

### Changed
- **BREAKING**: Drop Node 10.x support.
- **BREAKING**: Change data model and validation of keystore configs. Configs
  no longer include `invoker` or `delegator` properties.

## 3.2.0 - 2021-02-10

### Added
- Added validators to `keystore`, `keystores`, `authorizations`, and
  `zcaps` endpoints.
- Improve test coverage.

## 3.1.0 - 2021-01-12

### Changed
- Update bedrock-account@5.0

## 3.0.0 - 2020-09-22

### Changed
- **BREAKING**: Do not look up zcaps in authorizations collection;
  full zcap chain must be submitted. A future feature may involve
  ensuring that zcaps for certain keys are present in the
  authorizations collection as an added security measure, but
  those zcaps would still need to be submitted at invocation.

## 2.3.0 - 2020-06-30

### Changed
- Update peerDependencies to include bedrock-account@4.
- Update test deps.
- Update CI workflow.

## 2.2.0 - 2020-06-19

### Added
- Improve test coverage.

### Changed
- Update peer deps.
- Improve error handling in `_verifyHost` helper.

## 2.1.0 - 2020-05-15

### Added
- Add CORS support for key ops.

### Changed
- Use bedrock-kms@2.1.0.

## 2.0.0 - 2020-04-02

### Added
- Create expectedRootCapability for revocations.

### Changed
- **BREAKING**: Use webkms-switch@2.
- **BREAKING**: Use http-signature-zcap-verify@3.

## 1.2.1 - 2020-02-27

### Fixed
- Fix syntax error/typo.

## 1.2.0 - 2020-02-26

### Added
- Revocations API.

### Changed
- Use jsonld-signatures@5.

## 1.1.3 - 2020-01-22

### Fixed
- Add missing jsonld-sigatures dep.

## 1.1.2 - 2020-01-12

### Fixed
- Ensure local zcap storage is checked for invoked zcaps.

## 1.1.1 - 2020-01-12

### Fixed
- Ensure local zcap storage is checked for parent zcaps.

## 1.1.0 - 2020-01-11

### Added
- Support delegation by non-root controllers provided that `delegator`
  is set in the zcap.

## 1.0.1 - 2019-12-20

### Fixed
- Fixed typo in module import.

## 1.0.0 - 2019-12-20

### Added
- Added core files.

- See git history for changes.
