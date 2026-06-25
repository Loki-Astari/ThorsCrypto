# Changelog

All notable changes to this project will be documented in this file.

This component is part of [ThorsAnvil](https://github.com/Loki-Astari/ThorsAnvil). See the [parent changelog](https://github.com/Loki-Astari/ThorsAnvil/blob/master/CHANGELOG.md) for full release history.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [11.0.0] - 2026-06-24

### Security
- Replaced `std::string::operator==` with `CRYPTO_memcmp` to prevent timing attacks
- Secured the random number generator
- Cleanup memory after use for secure data (zeroing sensitive buffers)
- Limited iteration count in PBKDF2 to prevent DoS attacks

### Fixed
- Fixed variable shadowing in `Pbkdf2::hash`
- Fixed race condition
- Removed unneeded diagnostic message

### Changed
- Updated build tools
- Updated logging to be consistent
