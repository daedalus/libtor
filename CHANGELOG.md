# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SQLite-based ntor key cache (`DescriptorCache`) with TTL eviction
- Stale key cooldown mechanism (1 hour before retry)
- ntor-v3 handshake implementation with legacy ntor fallback
- Guard state persistence (`GuardSelection`, `GuardState`)
- Bootstrap flow that fetches directory through Tor circuit
- Consensus parser fix for r-line timestamp format

### Changed
- Circuit creation tries ntor-v3 first, falls back to legacy ntor

## [0.1.0] - Initial Release

### Added
- TLS connection to Tor relays
- Link protocol negotiation (VERSIONS, CERTS, NETINFO)
- Circuit creation (CREATE_FAST, CREATE2)
- ntor handshake for circuit extension
- Onion-encrypted relay cells (AES-128-CTR + SHA-1)
- Stream multiplexing (BEGIN/DATA/END)
- Directory client for consensus fetching
- DNS-over-Tor resolution
- SOCKS4/5 proxy server
- YAML configuration file support
- Environment variable configuration
