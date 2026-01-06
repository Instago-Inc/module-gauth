# module/gauth - V8 module

`gauth` is a small helper for connecting to Google APIs in workflows without dragging in heavy dependencies. It keeps OAuth tokens in-memory for the current run, so you can focus on the workflow logic.

It is designed for the lightweight V8 runtime used at https://instago.ai and fits cleanly into flow steps and utility modules.

## Technical reference

Exports:
- `configure({ clientId, clientSecret, refreshToken, tokenEndpoint?, scope?, scopes?, services? })`
- `setTokens({ accessToken?, refreshToken?, expiresAt?, obtainedAt?, scope?, scopes?, services? })`
- `clear({ scope?, scopes?, services? }?)`
- `getAccessToken({ scope?, scopes?, services? }?)`
- `forceRefresh({ scope?, scopes?, services? }?)`
- `authorizationHeader()`
- `getToken({ scope?, scopes?, services? }?)`
- `auth({ scope?, scopes?, services? }?)`
- `toJSON()`

Configuration:
- Environment variables (optional):
  - `gauth.clientId`
  - `gauth.clientSecret`
  - `gauth.refreshToken`
  - `gauth.scope`
  - `gauth.tokenEndpoint`
  - `google.scope`
- `configure(...)` sets default credentials; passing `scope`/`scopes`/`services` will configure a scoped entry and reset its cached access token.
- Scope inputs accept a string (space/comma separated), JSON array string, or array. Alias `:ro` is mapped to `.readonly`. Use `all` or `*` to expand all known built-in scopes.

Usage:
- `getAccessToken(...)` exchanges the refresh token when needed and resolves to an access token string.
- `getToken(...)` returns `{ status, tokens }` with `access_token`, `expires_in`, `obtained_at`, and `scope`.
- `auth(...)` is a convenience wrapper that returns the token string or `''` on error.
- `authorizationHeader()` resolves to a single header string `Authorization: Bearer ...`.
- `clear(...)` drops cached access tokens for a scope or all scopes.

Examples:
```js
const gauth = require('gauth@latest');

gauth.configure({
  clientId: env.GOOGLE_CLIENT_ID,
  clientSecret: env.GOOGLE_CLIENT_SECRET,
  refreshToken: env.GOOGLE_REFRESH_TOKEN,
  scope: 'gmail.readonly'
});

const token = await gauth.getAccessToken();
```

```js
const gauth = require('gauth@latest');

const res = await gauth.getToken({ services: ['sheets', 'drive.readonly'] });
if (res.status === 'ok') {
  const authHeader = await gauth.authorizationHeader();
  console.log('auth ready', authHeader);
}
```
