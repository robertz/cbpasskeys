# Changelog

**0.1.0**
- First release: a CFML port of [bx-passkeys](https://github.com/robertz/bx-passkeys) 0.2.0
  for ColdBox on Lucee 6+ and Adobe ColdFusion 2023+, with the same checks and API.
- WireBox mappings `RelyingParty@cbpasskeys`, `TableCredentialStore@cbpasskeys` and
  `MemoryCredentialStore@cbpasskeys`; the store is picked with the `credentialStore` setting.
- `TableCredentialStore` takes `unicodeNames` (default `true`) to bind passkey names as
  nvarchar, for drivers without national types.
- `MemoryCredentialStore` compares credential ids case-sensitively.
