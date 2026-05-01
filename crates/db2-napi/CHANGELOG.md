# Changelog

All notable changes to this package will be documented in this file.

## [0.1.7-zos.17](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.17) (2026-05-01)

### Bug Fixes

- skip LUW post-auth initialization for Db2 for z/OS servers

## [0.1.7-zos.16](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.16) (2026-05-01)

### Bug Fixes

- omit ACCRDB CRRTKN for z/OS hosts that reject 0x2135

## [0.1.7-zos.15](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.15) (2026-05-01)

### Bug Fixes

- omit CCSIDCMN from ACCRDB TYPDEFOVR for z/OS hosts that reject 0x1191

## [0.1.7-zos.14](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.14) (2026-05-01)

### Bug Fixes

- encode ACCRDB TYPDEFNAM and related character fields as JCC-compatible UTF-8 bytes

## [0.1.7-zos.13](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.13) (2026-05-01)

### Bug Fixes

- omit ACCRDB TYPDEFNAM/TYPDEFOVR by default for z/OS servers that reject type negotiation

## [0.1.7-zos.12](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.12) (2026-05-01)

### Bug Fixes

- default ACCRDB to QTDSQL370 and expose typeDefinitionName for z/OS TYPDEFNAM testing

## [0.1.7-zos.11](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.11) (2026-05-01)

### Bug Fixes

- use JCC-compatible QTDSQLASC type definition negotiation for z/OS ACCRDB

## [0.1.7-zos.10](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.10) (2026-05-01)

### Bug Fixes

- send z/OS RDBNAM as the trimmed location-name length instead of an 18-byte padded value

## [0.1.7-zos.9](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.9) (2026-05-01)

### Bug Fixes

- default JS encrypted authentication to AES for the current Db2 z/OS/JCC path

## [0.1.7-zos.8](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.8) (2026-05-01)

### Bug Fixes

- keep z/OS RDBNAM reserved bytes blank and lock SECMEC 7 AES to an IBM JCC test vector

## [0.1.7-zos.7](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.7) (2026-05-01)

### Bug Fixes

- force JCC-compatible UTF-8 password plaintext for SECMEC 7 AES authentication

## [0.1.7-zos.6](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.6) (2026-05-01)

### Bug Fixes

- use the server security token IV for SECMEC 7 AES encrypted password authentication

## [0.1.7-zos.5](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.5) (2026-05-01)

### Bug Fixes

- publish prerelease npm builds with the zos dist-tag

## [0.1.7-zos.4](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.4) (2026-05-01)

### Bug Fixes

- align AES encrypted authentication with IBM JCC's 64-byte Diffie-Hellman token and AES key derivation

## [0.1.7-zos.3](https://github.com/gurungabit/db2-node/releases/tag/zos-secmec7-0.1.7-zos.3) (2026-05-01)

### Bug Fixes

- add AES encrypted credential negotiation for DB2 z/OS authentication

## [0.1.6](https://github.com/gurungabit/db2-node/compare/v0.1.5...v0.1.6) (2026-05-01)


### Bug Fixes

* support configurable db2 security mechanism ([cc11e61](https://github.com/gurungabit/db2-node/commit/cc11e61d7316a8ddc0fc04e38fb725c3051af97a))

## [0.1.5](https://github.com/gurungabit/db2-node/compare/v0.1.4...v0.1.5) (2026-05-01)


### Bug Fixes

* omit RDBNAM from SECCHK for zOS ([0ef44bc](https://github.com/gurungabit/db2-node/commit/0ef44bc6eec84b312bd9bec674ebd0b0b354b5dd))

## [0.1.4](https://github.com/gurungabit/db2-node/compare/v0.1.3...v0.1.4) (2026-04-30)


### Bug Fixes

* publish zOS auth fixes through npm package ([025e6c9](https://github.com/gurungabit/db2-node/commit/025e6c99400a6892d1bac72f96c92adfb3fa753c))

## [0.1.3](https://github.com/gurungabit/db2-node/compare/v0.1.2...v0.1.3) (2026-04-30)

### Bug Fixes

- release DB2 zOS authentication support ([2df2565](https://github.com/gurungabit/db2-node/commit/2df256539796156f84aeb046d574b7dfaba98011))

## [0.1.2](https://github.com/gurungabit/db2-node/compare/v0.1.1...v0.1.2) (2026-04-07)

### Bug Fixes

- return numeric DB2 values as JSON numbers, not strings ([8a495d7](https://github.com/gurungabit/db2-node/commit/8a495d78d8bc1116fc09cc026e24406900ce1b05))

## [0.1.1] - 2026-04-06

- Scope the package as `@gurungabit/db2-node`
- Bundle prebuilt native binaries into a single npm package
- Add MIT licensing metadata and package license file
- Add `release-please` automation for future releases
- Refresh docs publishing for the renamed GitHub Pages site

## [0.1.0] - 2026-04-06

- Initial public release of `@gurungabit/db2-node`
