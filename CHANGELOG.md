# bedrock-kms-http ChangeLog

## 4.1.0 - TBD

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
