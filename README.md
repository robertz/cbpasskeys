# cbpasskeys

WebAuthn passkeys for ColdBox: let people register a passkey and sign in with it, no password. It runs on Lucee and Adobe ColdFusion and uses only JDK crypto (`java.security`), with no third-party jars.

It's the CFML sibling of [bx-passkeys](https://github.com/robertz/bx-passkeys) for BoxLang, with the same checks and the same API.

- Attestation `"none"`: it trusts the key the authenticator hands over and doesn't check where the authenticator came from. That's what nearly every site wants.
- ES256 (P-256), Ed25519 and RS256: the three algorithms browsers actually use.
- It reads the new key from the COSE key inside the authenticator data, and checks the browser's `getPublicKey()` (SPKI) copy against it when one is sent. A small CBOR decoder is built in.
- Each challenge is kept in the session. It works once and expires after `challengeSeconds`.
- Passkeys live in a **credential store** you choose. A table-backed store and an in-memory store come with the module.
- No routes or handlers of its own: you call four methods from your handlers.

## Requirements

- ColdBox 7+
- Lucee 6+ or Adobe ColdFusion 2023+
- Java 17+ (Ed25519 needs 15+)

Tested on Lucee 6.2 and Adobe ColdFusion 2023 (update 26) on Java 21, against Derby and MySQL 8.4.

## Install

```bash
box install cbpasskeys
```

## Settings

In `config/ColdBox.cfc`:

```js
moduleSettings = {
	cbpasskeys : {
		rpId    : "example.com",
		rpName  : "Example",
		origins : [ "https://example.com" ],
		store   : { datasource: "app", table: "passkey_credentials" }
	}
};
```

| Setting | Default | Meaning |
|---|---|---|
| `rpId` | `"localhost"` | Your site's domain. Passkeys are bound to it. |
| `rpName` | the rpId | The name shown in the browser's passkey sheet. |
| `origins` | `[]` | The exact origins sign-ins may come from, e.g. `[ "https://example.com" ]`. When it's empty, the module allows `https` on the rpId itself (any port), and plain `http` only on `localhost`. |
| `allowSubdomains` | `false` | With `origins` empty, also allow `https` on any subdomain of the rpId. Leave it off if anyone else can serve pages on a subdomain (user content, previews): such a page could relay sign-ins. |
| `challengeSeconds` | `300` | How long a challenge stays good. This is also the browser's timeout. |
| `algorithms` | `[ -7, -8, -257 ]` | COSE algorithm ids to accept, in order of preference. |
| `userVerification` | `"preferred"` | Set it to `"required"` to refuse an authenticator that didn't check a PIN or biometric. |
| `residentKey` | `"required"` | Discoverable credentials, so people can sign in without typing a username. |
| `maxPerUser` | `0` | The most passkeys one user may have. `0` means no limit. |
| `sessionKey` | `"passkeyChallenge"` | The session key where pending challenges are kept, one for registration and one for sign-in. |
| `credentialStore` | `"TableCredentialStore@cbpasskeys"` | The WireBox id of the store to use. |
| `store` | `{ table, datasource, unicodeNames }` | Settings for `TableCredentialStore`. |

## The table

Create it from `sql/mssql.sql`, `sql/mysql.sql` or `sql/postgres.sql`. The MSSQL one:

```sql
CREATE TABLE passkey_credentials (
	credential_id VARCHAR(1400) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY NONCLUSTERED,
	user_id       VARCHAR(255)  COLLATE Latin1_General_100_BIN2 NOT NULL,
	public_key    VARCHAR(2048) NOT NULL,
	algorithm     INT           NOT NULL,
	sign_count    BIGINT        NOT NULL DEFAULT 0,
	transports    VARCHAR(255)  NULL,
	name          NVARCHAR(100) NOT NULL,
	created_at    DATETIME2     NOT NULL,
	last_used_at  DATETIME2     NULL
);
CREATE INDEX ix_passkey_credentials_user ON passkey_credentials ( user_id );
```

The scripts give `credential_id` and `user_id` binary collations, so they compare case-sensitively. Keep that if you write your own: credential ids are base64url, where `a` and `A` differ.

`TableCredentialStore` binds the passkey name as `cf_sql_nvarchar`, which MSSQL needs to keep non-ASCII names. For a driver without national types (Derby), set `store.unicodeNames: false`.

## Usage

Inject the relying party, a singleton:

```js
property name="passkeys" inject="RelyingParty@cbpasskeys";
```

Every method that takes `sessionData` reads or writes the session struct you give it. Pass `session`.

### Routes

```js
// config/Router.cfc
post( "/passkeys/options" ).to( "passkeys.registrationOptions" );
post( "/passkeys" ).to( "passkeys.register" );
post( "/sign-in/passkey/options" ).to( "passkeys.signInOptions" );
post( "/sign-in/passkey" ).to( "passkeys.signIn" );
```

### A handler

This one uses [cbauth](https://forgebox.io/view/cbauth) for the signed-in user. Any sign-in works the same way.

```js
component {

	property name="passkeys"    inject="RelyingParty@cbpasskeys";
	property name="userService" inject="UserService";

	// the user is already signed in some other way
	function registrationOptions( event, rc, prc ) {
		var user = auth().getUser();
		try {
			return event.renderData(
				type = "json",
				data = passkeys.registrationOptions( { id: user.getId(), name: user.getEmail(), displayName: user.getName() }, session )
			);
		} catch ( "Passkeys.Invalid" e ) {
			return event.renderData( type = "json", data = { "error": e.message }, statusCode = 400 );
		}
	}

	function register( event, rc, prc ) {
		try {
			var credential = passkeys.register( { id: auth().getUserId() }, session, event.getHTTPContent( json = true ) );
			return event.renderData( type = "json", data = { "id": credential.credentialId, "name": credential.name } );
		} catch ( "Passkeys.Invalid" e ) {
			return event.renderData( type = "json", data = { "error": e.message }, statusCode = 400 );
		}
	}

	function signInOptions( event, rc, prc ) {
		return event.renderData( type = "json", data = passkeys.signInOptions( session ) );
	}

	function signIn( event, rc, prc ) {
		var result = {};
		try {
			result = passkeys.verify( session, event.getHTTPContent( json = true ) );
		} catch ( "Passkeys.Invalid" e ) {
			return event.renderData( type = "json", data = { "error": e.message }, statusCode = 401 );
		}
		sessionRotate();
		auth().login( userService.retrieveUserById( result.userId ) );
		return event.renderData( type = "json", data = { "signedIn": true } );
	}

}
```

`user.id` is your app's id for the user, sent to the authenticator as UTF-8 bytes (at most 64). Don't put names or emails in it.

`verify()` returns `{ userId, credentialId, userVerified, signCount, credential }`. Call `sessionRotate()` before you sign the user in, so a session id someone learned before sign-in is useless after it.

Protect these routes from CSRF the way you protect your other POST routes, with [cbcsrf](https://forgebox.io/view/cbcsrf) for example.

To re-confirm a user who is already signed in (before a sensitive action, say), pass their id: `passkeys.signInOptions( session, user.getId() )`. Only that user's passkeys are offered, and `verify()` refuses anyone else's.

To list or remove a user's passkeys in your account settings, call the store: `passkeys.getStore().listForUser( userId )`. Before `remove()`, check that the passkey is in that list, and compare ids with `compare()`, not `==`, which ignores case.

`test-harness/handlers/Passkeys.cfc` is a complete handler with list and remove, and `test-harness/tests/specs/PasskeyHandlerSpec.cfc` drives it.

### In the browser

`client/passkeys.js` is a small ES module, with types in `client/passkeys.d.ts`. Copy it into your front end:

```js
import { createPasskey, signWithPasskey, passkeysSupported } from './passkeys.js'

const post = (path, body) => fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) }).then((r) => r.json())

// add a passkey
const registration = await createPasskey(await post('/passkeys/options'))
if (registration) await post('/passkeys', registration)

// sign in
const assertion = await signWithPasskey(await post('/sign-in/passkey/options'))
if (assertion) await post('/sign-in/passkey', assertion)
```

Both functions return `null` when the person closes the browser's sheet.

## Credential stores

A store implements `cbpasskeys.models.CredentialStore`:

```js
function findByCredentialId( required string credentialId );   // struct or null
array function listForUser( required string userId );          // newest first
void function add( required struct credential );
boolean function updateUsage( required string credentialId, required numeric signCount, required date lastUsedAt );
boolean function remove( required string credentialId );
```

A credential is `{ credentialId, userId, publicKey, algorithm, signCount, transports, name, createdAt, lastUsedAt }`. `credentialId` and `publicKey` (SPKI) are base64url strings. Compare `credentialId` and `userId` case-sensitively.

`updateUsage` must check and write in one step: save only while the new `signCount` is above the stored one (or both are 0), and return whether it saved. That's what keeps two sign-ins racing with the same counter from both getting through.

To use your own store, map it in WireBox and name it in the settings:

```js
// config/WireBox.cfc
map( "PasskeyStore" ).to( "models.PasskeyStore" ).asSingleton();

// config/ColdBox.cfc
moduleSettings = { cbpasskeys : { credentialStore : "PasskeyStore" } };
```

- **`TableCredentialStore@cbpasskeys`** uses one table with plain parameterized SQL.
- **`MemoryCredentialStore@cbpasskeys`** holds passkeys in memory, for tests and demos.

## What it checks

On **registration**:

- The challenge is the one in the session, for registration, still in date, and for the same user. Taking it is locked per session, so one challenge can't be used twice at once.
- `clientDataJSON` has type `webauthn.create`, an allowed origin, and isn't from a cross-origin frame.
- `authenticatorData` carries the SHA-256 of the rpId, the user-present flag (and the user-verified flag when that's required), and attested credential data.
- The credential id matches the one in `authenticatorData` and is at most 1023 bytes. It's stored in canonical base64url, whatever padding the browser sent.
- `authenticatorData` carries the COSE key, which is one of the accepted algorithms and can be read. When the browser also sends an SPKI key, it must be the same key.
- The user is still under `maxPerUser`.
- The passkey isn't already registered to another user.

On **sign-in**, the same challenge, origin, rpId and flag checks apply, plus:

- The credential is on file.
- It belongs to the expected user, if one was given, and matches `userHandle`, if the browser sent one.
- Its algorithm is still one of the accepted `algorithms`.
- The signature over `authenticatorData ‖ SHA-256(clientDataJSON)` verifies.
- The signature counter moves forward, unless it's 0 and always has been (most passkeys always send 0). A counter that stays put, goes backwards or drops to 0 suggests a cloned key. The store saves the new counter only if it's still ahead, so two sign-ins racing with one counter can't both succeed.

Every refusal throws `Passkeys.Invalid` with a message you can show the user. A bad setting throws `Passkeys.Configuration`.

The module doesn't do attestation verification, authenticator metadata (MDS) or any extensions.

## Engine notes

- **The options keep their JSON types.** Their keys are quoted and their numbers and booleans are Java-typed, so Adobe CF's `serializeJSON` keeps key case and doesn't turn a numeric-looking name like `"1001"` into a number.
- **Adobe CF's `?:` treats `0` and `false` as missing.** The module doesn't rely on `?:` where either can occur, so a user id of `0` works. Watch for it in your own code.
- **`updateUsage` relies on the driver's update count.** Adobe CF reports 1 for an UPDATE that matched no rows through a generic JDBC driver on Derby, which would let the counter race through. MySQL Connector/J on Adobe CF, and every driver tried on Lucee, report it correctly. On another driver, check that `updateUsage` returns `false` for a counter that doesn't move forward.
- **Adobe CF and Java modules.** Adobe CF calls Java methods through the runtime class, which Java 17+ doesn't open for the JDK's key classes, so the module calls key methods through their public interfaces. No JVM flags are needed.

## Development

The test harness is a small ColdBox app in `test-harness/` with a CommandBox server file per engine.

```bash
cd test-harness && box install
```

Put an Apache Derby 10.15+ embedded jar at `test-harness/lib/derby.jar` (the table-store specs use an in-memory Derby database). Then run every engine:

```bash
bash scripts/test.sh
```

Or one engine: `bash scripts/test.sh lucee@6`.

For line coverage of the module's code, run:

```bash
bash scripts/coverage.sh
```

It turns on Lucee's execution log for the Lucee 6 server, runs the specs, maps every executed statement back to its source line, and fails if any code line in `ModuleConfig.cfc` or `models/` never ran. TestBox's own coverage needs FusionReactor, which this doesn't. It counts lines inside functions, since Lucee doesn't log a component's pseudo-constructor. It measures lines, not every outcome of every condition.

To run the table-store specs on MySQL too, put a MySQL Connector/J jar in `test-harness/lib/` and its connection in `test-harness/.env`:

```bash
CBPASSKEYS_MYSQL_URL=jdbc:mysql://127.0.0.1:3306/cbpasskeys?useSSL=false&allowPublicKeyRetrieval=true
CBPASSKEYS_MYSQL_USER=root
CBPASSKEYS_MYSQL_PASSWORD=...
```

## License

MIT
