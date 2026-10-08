# Changelog

## 1.0.0

### Added

- Adds the Vault auth type to hosts
- Sign in to Vault with OIDC when you connect
- Never stores a Vault token or long-lived key
- Reusable signer profiles you can share with everyone

### Fixed

- A personal Vault profile can no longer point the server at private or internal addresses unless an admin allows that host
