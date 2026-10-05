# Contributing to HashiCorp Vault

## Development

```bash
npm run build      # build into dist/
npm run test       # run this plugin's tests
npm run typecheck  # type-check this plugin
npm run validate   # check manifest.json
npm run format     # format the code with Prettier
```

## Settings

### Admin

- **Redirect URI:** add `<base URL>/plugin-api/vault/oidc/callback` to `allowed_redirect_uris` in each Vault OIDC role

### Host

- **Vault signer profile:** the profile this host uses

## Permissions

- `vault.use`: create signer profiles and connect to hosts that use Vault. Admins and users have it by default.
- `vault.share`: share a profile so every user can pick it. Only admins have it by default.
