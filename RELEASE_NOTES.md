# Oura Ring 0.2.7

- Adds OAuth sign-in using your own Oura application's client ID and secret, requesting only daily data access.
- Refreshes access tokens automatically and reports authentication failures before modifying notes.
- Preserves existing personal access tokens until OAuth connects successfully or you disconnect.
- Adds callback validation, manual sign-in completion, and safe handling of single-use refresh tokens.

See the README for OAuth setup. Credentials and tokens are stored unencrypted in the vault's plugin data.json; keep this file private and avoid syncing it between devices.

Validation: automated authentication tests, TypeScript checks, and the production build. Live Oura acceptance of the obsidian:// callback, browser handoff, mobile behavior, and rendered settings have not yet been verified. A manual HTTPS callback option is available.
