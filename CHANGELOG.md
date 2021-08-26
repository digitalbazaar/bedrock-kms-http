# bedrock-kms-http ChangeLog

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
