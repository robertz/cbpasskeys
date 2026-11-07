/** Registering passkeys and signing in with them, and every answer that must be refused. */
component extends="testbox.system.BaseSpec" {

	private function party( struct settings = {}, store ) {
		var merged = { rpId: "localhost", rpName: "Spec" };
		structAppend( merged, arguments.settings, true );
		return new cbpasskeys.models.RelyingParty( merged, arguments.store ?: new cbpasskeys.models.MemoryCredentialStore() );
	}

	private function fake( numeric algorithm = -7, string rpId = "localhost" ) {
		return new tests.helpers.FakeAuthenticator( algorithm = arguments.algorithm, rpId = arguments.rpId );
	}

	private struct function enrol( required rp, required authenticator, struct user = { id: "1", name: "alice" }, struct changes = {}, array drop = [] ) {
		var sessionData = {};
		var options = arguments.rp.registrationOptions( arguments.user, sessionData );
		return arguments.rp.register( arguments.user, sessionData, arguments.authenticator.create( options, arguments.changes, arguments.drop ) );
	}

	private function refused( required rp, required struct held, required struct reply, string message = "" ) {
		var expected = arguments.message;
		var target = arguments.rp;
		var sessionData = arguments.held;
		var answer = arguments.reply;
		expect( () => target.verify( sessionData, answer ) ).toThrow( "Passkeys.Invalid", expected );
	}



	function run() {

		describe( "Registration options", () => {

			it( "asks for attestation none, the configured algorithms, and the user's id as bytes", () => {
				var rp = party( { algorithms: [ -8, -7 ], rpName: "Example" } )
				var sessionData = {}
				var options = rp.registrationOptions( { id: 42, name: "alice", displayName: "Alice A." }, sessionData )
				expect( options.rp ).toBe( { id: "localhost", name: "Example" } )
				expect( options.attestation ).toBe( "none" )
				expect( options.pubKeyCredParams.map( ( p ) => p.alg ) ).toBe( [ -8, -7 ] )
				expect( options.user.id ).toBe( "NDI" )
				expect( options.user.displayName ).toBe( "Alice A." )
				expect( options.timeout ).toBe( 300000 )
				expect( options.authenticatorSelection.residentKey ).toBe( "required" )
				expect( options.excludeCredentials ).toBeEmpty()
				expect( sessionData.passkeyChallenge.register.value ).toBe( options.challenge )
			} )

			it( "doesn't offer a device that already holds one of the user's passkeys", () => {
				var rp = party()
				var key = fake()
				enrol( rp, key )
				var options = rp.registrationOptions( { id: "1", name: "alice" }, {} )
				expect( options.excludeCredentials ).toHaveLength( 1 )
				expect( options.excludeCredentials[ 1 ].id ).toBe( key.getCredentialId() )
				expect( options.excludeCredentials[ 1 ].transports ).toBe( [ "internal" ] )
			} )

			it( "stops at maxPerUser", () => {
				var rp = party( { maxPerUser: 1 } )
				enrol( rp, fake() )
				expect( () => rp.registrationOptions( { id: "1", name: "alice" }, {} ) ).toThrow( "Passkeys.Invalid" )
			} )

			it( "takes a user id of 0", () => {
				var options = party().registrationOptions( { id: 0, name: "root" }, {} )
				expect( options.user.id ).toBe( "MA" )
			} )

			it( "keeps its challenge under the configured session key", () => {
				var rp = party( { sessionKey: "webauthn" } )
				var sessionData = {}
				var options = rp.registrationOptions( { id: "1", name: "alice" }, sessionData )
				expect( sessionData.webauthn.register.value ).toBe( options.challenge )
				expect( sessionData ).notToHaveKey( "passkeyChallenge" )
			} )

			it( "refuses settings it can't honour", () => {
				expect( () => party( { algorithms: [ -35 ] } ) ).toThrow( "Passkeys.Configuration" )
				expect( () => party( { rpId: "" } ) ).toThrow( "Passkeys.Configuration" )
				expect( () => party().registrationOptions( { id: "", name: "x" }, {} ) ).toThrow( "Passkeys.Configuration" )
			} )

		} )

		describe( "Registering and signing in", () => {

			for ( var algorithm in [ -7, -8, -257 ] ) {
				it( "works for algorithm #algorithm# from the browser's SPKI key", ( data ) => {
					var rp = party()
					var key = fake( data.algorithm )
					var saved = enrol( rp, key, { id: "1", name: "alice" }, {}, [ "attestationObject" ] )
					expect( saved.algorithm ).toBe( data.algorithm )
					expect( saved.userId ).toBe( "1" )
					var sessionData = {}
					var result = rp.verify( sessionData, key.get( rp.signInOptions( sessionData ) ) )
					expect( result.userId ).toBe( "1" )
					expect( result.credentialId ).toBe( key.getCredentialId() )
					expect( result.userVerified ).toBeTrue()
				}, [], false, { algorithm: algorithm } );

				it( "works for algorithm #algorithm# from attestationObject alone", ( data ) => {
					var rp = party()
					var key = fake( data.algorithm )
					var saved = enrol( rp, key, { id: "1", name: "alice" }, {}, [ "publicKey", "publicKeyAlgorithm", "authenticatorData" ] )
					expect( saved.algorithm ).toBe( data.algorithm )
					var sessionData = {}
					expect( rp.verify( sessionData, key.get( rp.signInOptions( sessionData ) ) ).userId ).toBe( "1" )
				}, [], false, { algorithm: algorithm } );
			}

			it( "gets the same key from SPKI and from the COSE key", () => {
				var rp = party()
				var key = fake()
				var fromSpki = enrol( rp, key, { id: "1", name: "alice" }, {}, [ "attestationObject" ] )
				var other = party()
				var fromCose = enrol( other, key, { id: "1", name: "alice" }, {}, [ "publicKey" ] )
				expect( fromCose.publicKey ).toBe( fromSpki.publicKey )
			} )

			it( "keeps the sign count and the time of last use", () => {
				var store = new cbpasskeys.models.MemoryCredentialStore()
				var rp = party( {}, store )
				var key = fake()
				enrol( rp, key )
				var fresh = store.findByCredentialId( key.getCredentialId() )
				expect( isNull( fresh.lastUsedAt ) ).toBeTrue()
				var sessionData = {}
				rp.verify( sessionData, key.get( rp.signInOptions( sessionData ) ) )
				var held = store.findByCredentialId( key.getCredentialId() )
				expect( held.signCount ).toBe( 1 )
				expect( isDate( held.lastUsedAt ) ).toBeTrue()
			} )

			it( "offers only that user's passkeys when confirming a signed-in user", () => {
				var rp = party()
				var mine = fake()
				var theirs = fake()
				enrol( rp, mine )
				enrol( rp, theirs, { id: "2", name: "bob" } )
				var sessionData = {}
				var options = rp.signInOptions( sessionData, "1" )
				expect( options.allowCredentials.map( ( c ) => c.id ) ).toBe( [ mine.getCredentialId() ] )
				refused( rp, sessionData, theirs.get( options ), "another account" )
				options = rp.signInOptions( sessionData, "1" )
				expect( rp.verify( sessionData, mine.get( options ) ).userId ).toBe( "1" )
			} )

			it( "keeps a registration challenge while a sign-in is started in the same session", () => {
				var rp = party()
				var key = fake()
				var sessionData = {}
				var creation = rp.registrationOptions( { id: "1", name: "alice" }, sessionData )
				rp.signInOptions( sessionData )
				var saved = rp.register( { id: "1", name: "alice" }, sessionData, key.create( creation ) )
				expect( saved.credentialId ).toBe( key.getCredentialId() )
			} )

			it( "stores the canonical credential id, whatever padding the browser sent", () => {
				var rp = party()
				var key = fake()
				var saved = enrol( rp, key, { id: "1", name: "alice" }, { id: key.getCredentialId() & "==" } )
				expect( saved.credentialId ).toBe( key.getCredentialId() )
				var sessionData = {}
				var answer = key.get( rp.signInOptions( sessionData ) )
				answer.id &= "=="
				expect( rp.verify( sessionData, answer ).credentialId ).toBe( key.getCredentialId() )
			} )

			it( "refuses a sign-in with an algorithm no longer accepted", () => {
				var store = new cbpasskeys.models.MemoryCredentialStore()
				var key = fake( -257 )
				enrol( party( {}, store ), key )
				var strict = party( { algorithms: [ -7 ] }, store )
				var sessionData = {}
				refused( strict, sessionData, key.get( strict.signInOptions( sessionData ) ), "kind of key" )
			} )

			it( "returns the passkey on file when the same one is registered twice", () => {
				var rp = party()
				var key = fake()
				enrol( rp, key )
				expect( enrol( rp, key ).credentialId ).toBe( key.getCredentialId() )
				expect( () => enrol( rp, key, { id: "2", name: "bob" } ) ).toThrow( "Passkeys.Invalid", "already in use" )
			} )

		} )

		describe( "Refusing registrations", () => {

			it( "refuses an id that isn't the authenticator's, a key that won't read, or an algorithm not offered", () => {
				var rp = party( { algorithms: [ -7 ] } )
				var key = fake()
				expect( () => enrol( rp, key, { id: "1", name: "alice" }, { id: "AAAAAAAAAAAAAAAAAAAAAA" } ) ).toThrow( "Passkeys.Invalid", "id doesn't match" )
				expect( () => enrol( rp, key, { id: "1", name: "alice" }, { publicKey: "bm90IGEga2V5" }, [ "attestationObject" ] ) ).toThrow( "Passkeys.Invalid" )
				expect( () => enrol( rp, key, { id: "1", name: "alice" }, { publicKeyAlgorithm: -999 }, [ "attestationObject" ] ) ).toThrow( "Passkeys.Invalid" )
				var ed = fake( -8 )
				expect( () => enrol( rp, ed ) ).toThrow( "Passkeys.Invalid", "kind of key" )
			} )

			it( "refuses an SPKI key that isn't the one in authenticatorData", () => {
				var rp = party()
				var key = fake()
				var stranger = fake()
				var swapped = stranger.create( { challenge: "x", user: { id: "MQ" } } ).publicKey
				expect( () => enrol( rp, key, { id: "1", name: "alice" }, { publicKey: swapped } ) ).toThrow( "Passkeys.Invalid", "doesn't match" )
			} )

			it( "refuses an answer to another account's registration, or a sign-in challenge", () => {
				var rp = party()
				var key = fake()
				var sessionData = {}
				var options = rp.registrationOptions( { id: "1", name: "alice" }, sessionData )
				expect( () => rp.register( { id: "2", name: "bob" }, sessionData, key.create( options ) ) ).toThrow( "Passkeys.Invalid", "another account" )
				options = rp.signInOptions( sessionData )
				expect( () => rp.register( { id: "1", name: "alice" }, sessionData, key.create( { challenge: options.challenge, user: { id: "MQ" } } ) ) ).toThrow( "Passkeys.Invalid", "already used" )
			} )

			it( "refuses a registration for another site", () => {
				var rp = party()
				var key = fake( rpId = "evil.example" )
				expect( () => enrol( rp, key ) ).toThrow( "Passkeys.Invalid", "another site" )
			} )

			it( "refuses authenticatorData whose attested credential data has no key", () => {
				var rp = party()
				var key = fake()
				var sessionData = {}
				var options = rp.registrationOptions( { id: "1", name: "alice" }, sessionData )
				var answer = key.create( options, {}, [ "attestationObject" ] )
				var data = createObject( "java", "java.util.Base64" ).getUrlDecoder().decode( answer.authenticatorData )
				var idLength = len( createObject( "java", "java.util.Base64" ).getUrlDecoder().decode( answer.id ) )
				var trimmed = createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", 55 + idLength ) ).array()
				createObject( "java", "java.lang.System" ).arraycopy( data, javacast( "int", 0 ), trimmed, javacast( "int", 0 ), javacast( "int", 55 + idLength ) )
				answer.authenticatorData = createObject( "java", "java.util.Base64" ).getUrlEncoder().withoutPadding().encodeToString( trimmed )
				expect( () => rp.register( { id: "1", name: "alice" }, sessionData, answer ) ).toThrow( "Passkeys.Invalid", "without its key" )
			} )

			it( "refuses a credential id over 1023 bytes", () => {
				var rp = party()
				var key = fake()
				var long = createObject( "java", "java.util.Base64" ).getUrlEncoder().withoutPadding().encodeToString( createObject( "java", "java.nio.ByteBuffer" ).allocate( 1024 ).array() )
				expect( () => enrol( rp, key, { id: "1", name: "alice" }, { id: long } ) ).toThrow( "Passkeys.Invalid", "too long" )
			} )

			it( "keeps at most a few distinct, well-formed transports", () => {
				var rp = party()
				var key = fake()
				var saved = enrol( rp, key, { id: "1", name: "alice" }, { transports: [ "usb", "usb", "nfc", "Bad,One", "a", "b", "c", "d", "e", "f", "g", "h", "i" ] } )
				expect( saved.transports ).toBe( [ "usb", "nfc", "a", "b", "c", "d", "e", "f", "g", "h" ] )
			} )

			it( "enforces maxPerUser at registration too", () => {
				var rp = party( { maxPerUser: 1 } )
				var sessionData = {}
				var options = rp.registrationOptions( { id: "1", name: "alice" }, sessionData )
				enrol( rp, fake() )
				expect( () => rp.register( { id: "1", name: "alice" }, sessionData, fake().create( options ) ) ).toThrow( "Passkeys.Invalid", "as many passkeys" )
			} )

			it( "refuses an attestationObject that isn't CBOR", () => {
				var rp = party()
				var key = fake()
				expect( () => enrol( rp, key, { id: "1", name: "alice" }, { attestationObject: "AAEC" } ) ).toThrow( "Passkeys.Invalid" )
			} )

		} )

		describe( "Refusing sign-ins", () => {

			beforeEach( () => {
				variables.rp = party()
				variables.key = fake()
				enrol( variables.rp, variables.key )
				variables.sessionData = {}
			} )

			it( "refuses a challenge the server never gave, and uses each one up", () => {
				rp.signInOptions( sessionData )
				refused( rp, sessionData, key.get( { challenge: "made-up" } ), "another try" )
				var options = rp.signInOptions( sessionData )
				try {
					rp.verify( sessionData, key.get( { challenge: "made-up" } ) )
				} catch ( "Passkeys.Invalid" e ) {
				}
				refused( rp, sessionData, key.get( options ), "already used" )
			} )

			it( "refuses an expired challenge", () => {
				var options = rp.signInOptions( sessionData )
				sessionData.passkeyChallenge[ "sign-in" ].expires = 1
				refused( rp, sessionData, key.get( options ), "too long" )
			} )

			it( "refuses another origin, and plain http anywhere but localhost", () => {
				var options = rp.signInOptions( sessionData )
				refused( rp, sessionData, key.setOrigin( "https://evil.example" ).get( options ), "another site" )
				options = rp.signInOptions( sessionData )
				refused( rp, sessionData, key.setOrigin( "http://localhost.evil.example" ).get( options ), "another site" )
				options = rp.signInOptions( sessionData )
				expect( rp.verify( sessionData, key.setOrigin( "https://localhost:8443" ).get( options ) ).userId ).toBe( "1" )
			} )

			it( "refuses a registration answer offered as a sign-in", () => {
				refused( rp, sessionData, key.get( rp.signInOptions( sessionData ), "webauthn.create" ), "something else" )
			} )

			it( "refuses a signature from a key that isn't the one on file", () => {
				refused( rp, sessionData, key.get( rp.signInOptions( sessionData ), "webauthn.get", fake() ), "signature" )
			} )

			it( "refuses a passkey it doesn't know", () => {
				refused( rp, sessionData, fake().get( rp.signInOptions( sessionData ) ), "isn't one this site knows" )
			} )

			it( "refuses an answer without user presence", () => {
				refused( rp, sessionData, key.get( rp.signInOptions( sessionData ), "webauthn.get", key, 0 ), "you were there" )
			} )

			it( "refuses an unverified user when userVerification is required", () => {
				var strict = party( { userVerification: "required" } )
				var strictKey = fake()
				enrol( strict, strictKey )
				refused( strict, sessionData, strictKey.get( strict.signInOptions( sessionData ), "webauthn.get", strictKey, 1 ), "it was you" )
				expect( strict.verify( sessionData, strictKey.get( strict.signInOptions( sessionData ) ) ).userVerified ).toBeTrue()
			} )

			it( "refuses a sign count that goes backwards", () => {
				rp.verify( sessionData, key.setCounter( 9 ).get( rp.signInOptions( sessionData ) ) )
				refused( rp, sessionData, key.setCounter( 3 ).get( rp.signInOptions( sessionData ) ), "copied" )
			} )

			it( "refuses a counter that drops back to 0, and keeps the stored one", () => {
				rp.verify( sessionData, key.setCounter( 41 ).get( rp.signInOptions( sessionData ) ) )
				refused( rp, sessionData, key.setCounter( -1 ).get( rp.signInOptions( sessionData ) ), "copied" )
				expect( rp.getStore().findByCredentialId( key.getCredentialId() ).signCount ).toBe( 42 )
			} )

			it( "refuses a sign-in the store says lost the race to a newer counter", () => {
				var store = new cbpasskeys.models.MemoryCredentialStore()
				var racer = fake()
				enrol( party( {}, store ), racer )
				store.updateUsage( racer.getCredentialId(), 7, now() )
				// reads as counter 0, as a request that loaded the row before the other one saved 7 would
				var stale = party( {}, new tests.helpers.StaleStore( store ) )
				refused( stale, sessionData, racer.setCounter( 4 ).get( stale.signInOptions( sessionData ) ), "copied" )
				expect( store.findByCredentialId( racer.getCredentialId() ).signCount ).toBe( 7 )
			} )

			it( "refuses a userHandle that isn't the passkey's user", () => {
				var answer = key.get( rp.signInOptions( sessionData ) )
				answer.userHandle = "Mg"
				refused( rp, sessionData, answer, "another account" )
			} )

		} )

		describe( "Origins", () => {

			it( "allows https on the rpId only, http only on localhost", () => {
				var rp = party( { rpId: "example.com" } )
				expect( rp.originAllowed( "https://example.com" ) ).toBeTrue()
				expect( rp.originAllowed( "https://example.com:8443" ) ).toBeTrue()
				expect( rp.originAllowed( "https://app.example.com" ) ).toBeFalse()
				expect( rp.originAllowed( "http://example.com" ) ).toBeFalse()
				expect( rp.originAllowed( "https://example.com.evil.net" ) ).toBeFalse()
				expect( rp.originAllowed( "https://notexample.com" ) ).toBeFalse()
				expect( rp.originAllowed( "https://example.com/path" ) ).toBeFalse()
			} )

			it( "allows subdomains when allowSubdomains is on", () => {
				var rp = party( { rpId: "example.com", allowSubdomains: true } )
				expect( rp.originAllowed( "https://app.example.com:8443" ) ).toBeTrue()
				expect( rp.originAllowed( "https://example.com.evil.net" ) ).toBeFalse()
				expect( rp.originAllowed( "http://app.example.com" ) ).toBeFalse()
			} )

			it( "allows exactly the configured origins when given", () => {
				var rp = party( { rpId: "example.com", origins: [ "https://example.com", "https://login.example.com/" ] } )
				expect( rp.originAllowed( "https://example.com" ) ).toBeTrue()
				expect( rp.originAllowed( "https://login.example.com" ) ).toBeTrue()
				expect( rp.originAllowed( "https://app.example.com" ) ).toBeFalse()
			} )

		} )

	}

}
