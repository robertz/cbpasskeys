/**
 * The server half of WebAuthn passkeys, with attestation "none" and JDK crypto only.
 *
 * Registration takes the new key from the COSE key inside the authenticator data,
 * and checks the browser's SPKI copy (getPublicKey()) against it when one is sent.
 * A sign-in is the authenticator's signature over
 * authenticatorData + SHA-256(clientDataJSON), checked with java.security.Signature.
 * Each challenge lives in a session struct the caller passes in, one per purpose
 * (registration, sign-in), and is good for one try within challengeSeconds.
 */
component accessors="true" {

	property name="settings";
	property name="store";

	variables.SUPPORTED = {
		"-7"   : { key: "EC", signature: "SHA256withECDSA" },
		"-8"   : { key: "Ed25519", signature: "Ed25519" },
		"-257" : { key: "RSA", signature: "SHA256withRSA" }
	};
	variables.FLAG_USER_PRESENT = 1;
	variables.FLAG_USER_VERIFIED = 4;
	variables.FLAG_ATTESTED = 64;
	variables.MAX_CREDENTIAL_ID_BYTES = 1023;
	variables.MAX_TRANSPORTS = 10;
	variables.DEFAULTS = {
		rpId             : "localhost",
		rpName           : "",
		origins          : [],
		allowSubdomains  : false,
		challengeSeconds : 300,
		algorithms       : [ -7, -8, -257 ],
		userVerification : "preferred",
		residentKey      : "required",
		maxPerUser       : 0,
		sessionKey       : "passkeyChallenge"
	};

	/**
	 * settings: see DEFAULTS and the README. store: a CredentialStore.
	 */
	function init( required struct settings, required store ) {
		var merged = duplicate( variables.DEFAULTS );
		structAppend( merged, arguments.settings, true );
		variables.settings = merged;
		variables.store = arguments.store;
		merged.rpId = lCase( trim( merged.rpId ) );
		if ( !len( merged.rpId ) ) {
			throw( type = "Passkeys.Configuration", message = "rpId is required" );
		}
		if ( !len( merged.rpName ) ) {
			merged.rpName = merged.rpId;
		}
		if ( isSimpleValue( merged.origins ) ) {
			merged.origins = listToArray( merged.origins );
		}
		var origins = [];
		for ( var o in merged.origins ) {
			arrayAppend( origins, lCase( reReplace( trim( o ), "/+$", "" ) ) );
		}
		merged.origins = origins;
		var algorithms = [];
		for ( var a in merged.algorithms ) {
			var alg = toString( int( a ) );
			if ( !structKeyExists( variables.SUPPORTED, alg ) ) {
				throw( type = "Passkeys.Configuration", message = "Algorithm #alg# isn't supported; use -7, -8 or -257" );
			}
			arrayAppend( algorithms, alg );
		}
		merged.algorithms = algorithms;
		variables.random = createObject( "java", "java.security.SecureRandom" ).init();
		variables.urlEncoder = createObject( "java", "java.util.Base64" ).getUrlEncoder().withoutPadding();
		variables.urlDecoder = createObject( "java", "java.util.Base64" ).getUrlDecoder();
		variables.cbor = new Cbor();
		variables.cose = new CoseKey();
		return this;
	}

	/**
	 * PublicKeyCredentialCreationOptionsJSON for a new passkey.
	 * user: { id, name, displayName? }. id is your app's user id; it's handed to the
	 * authenticator as its UTF-8 bytes, so keep names and emails out of it.
	 */
	struct function registrationOptions( required struct user, required struct sessionData ) {
		var userId = userIdOf( arguments.user );
		var existing = variables.store.listForUser( userId );
		if ( variables.settings.maxPerUser > 0 && arrayLen( existing ) >= variables.settings.maxPerUser ) {
			invalid( "That's as many passkeys as an account can have. Remove one first." );
		}
		var name = toString( valueOf( arguments.user, "name", userId ) );
		var display = toString( valueOf( arguments.user, "displayName", "" ) );
		var params = [];
		for ( var alg in variables.settings.algorithms ) {
			arrayAppend( params, { "type": "public-key", "alg": javacast( "int", alg ) } );
		}
		var excluded = [];
		for ( var c in existing ) {
			arrayAppend( excluded, descriptor( c ) );
		}
		return {
			"challenge"              : newChallenge( arguments.sessionData, "register", userId ),
			"rp"                     : { "id": variables.settings.rpId, "name": variables.settings.rpName },
			"user"                   : { "id": encode( charsetDecode( userId, "utf-8" ) ), "name": name, "displayName": len( display ) ? display : name },
			"pubKeyCredParams"       : params,
			"timeout"                : javacast( "int", variables.settings.challengeSeconds * 1000 ),
			"attestation"            : "none",
			"authenticatorSelection" : {
				"residentKey"        : variables.settings.residentKey,
				"requireResidentKey" : javacast( "boolean", variables.settings.residentKey == "required" ),
				"userVerification"   : variables.settings.userVerification
			},
			"excludeCredentials" : excluded
		};
	}

	/**
	 * Checks the browser's answer and saves the new passkey; returns its credential struct.
	 * answer: { id, clientDataJSON, attestationObject?, authenticatorData?, publicKey?,
	 * publicKeyAlgorithm?, transports?: [], name? }, binary fields base64url. It needs
	 * attestationObject, or authenticatorData with publicKey and publicKeyAlgorithm.
	 * Throws Passkeys.Invalid.
	 */
	struct function register( required struct user, required struct sessionData, required struct answer ) {
		var userId = userIdOf( arguments.user );
		var held = takeChallenge( arguments.sessionData, "register" );
		if ( compare( held.userId, userId ) != 0 ) {
			invalid( "That answer is for another account. Try again." );
		}
		var idBytes = decodeField( arguments.answer, "id" );
		var credentialId = encode( idBytes );
		checkClientData( decodeField( arguments.answer, "clientDataJSON" ), "webauthn.create", held.value );

		var authData = "";
		if ( len( fieldOf( arguments.answer, "attestationObject" ) ) ) {
			var attestation = variables.cbor.decode( decodeField( arguments.answer, "attestationObject" ) );
			if ( !isStruct( attestation ) || !isBinary( attestation.authData ?: "" ) ) {
				invalid( "The authenticator's answer can't be read" );
			}
			authData = attestation.authData;
			if ( len( fieldOf( arguments.answer, "authenticatorData" ) ) && !sameBytes( authData, decodeField( arguments.answer, "authenticatorData" ) ) ) {
				invalid( "The authenticator's answer doesn't add up" );
			}
		} else {
			authData = decodeField( arguments.answer, "authenticatorData" );
		}
		var buffer = checkAuthData( authData );
		if ( !bitAnd( buffer.get( javacast( "int", 32 ) ), variables.FLAG_ATTESTED ) || len( authData ) < 55 ) {
			invalid( "That passkey came without its key" );
		}
		var idLength = createObject( "java", "java.lang.Short" ).toUnsignedInt( buffer.getShort( javacast( "int", 53 ) ) );
		if ( idLength > variables.MAX_CREDENTIAL_ID_BYTES || len( idBytes ) > variables.MAX_CREDENTIAL_ID_BYTES ) {
			invalid( "That passkey's id is too long" );
		}
		if ( len( authData ) < 55 + idLength || !sameBytes( slice( authData, 55, 55 + idLength ), idBytes ) ) {
			invalid( "That passkey's id doesn't match" );
		}
		// attested credential data must carry the key; the browser's SPKI is only a cross-check
		if ( len( authData ) <= 55 + idLength ) {
			invalid( "That passkey came without its key" );
		}
		var coseItem = variables.cbor.decodeAt( authData, 55 + idLength );
		if ( !isStruct( coseItem.value ) ) {
			invalid( "That passkey's key can't be read" );
		}
		var fromCose = variables.cose.toSpki( coseItem.value );
		var key = { algorithm: toString( fromCose.algorithm ), spki: encode( fromCose.spki ) };
		if ( len( fieldOf( arguments.answer, "publicKey" ) ) ) {
			if ( val( fieldOf( arguments.answer, "publicKeyAlgorithm" ) ) != val( key.algorithm ) || !sameBytes( decodeField( arguments.answer, "publicKey" ), fromCose.spki ) ) {
				invalid( "That passkey's key doesn't match the authenticator's" );
			}
		}
		if ( !arrayFind( variables.settings.algorithms, key.algorithm ) ) {
			invalid( "That passkey uses a kind of key this site doesn't take" );
		}
		publicKeyOf( key.spki, key.algorithm );

		var found = variables.store.findByCredentialId( credentialId );
		if ( !isNull( found ) ) {
			if ( compare( toString( found.userId ), userId ) != 0 ) {
				invalid( "That passkey is already in use" );
			}
			return found;
		}
		if ( variables.settings.maxPerUser > 0 && arrayLen( variables.store.listForUser( userId ) ) >= variables.settings.maxPerUser ) {
			invalid( "That's as many passkeys as an account can have. Remove one first." );
		}
		var transports = [];
		var offered = arguments.answer.transports ?: [];
		if ( isArray( offered ) ) {
			for ( var t in offered ) {
				if ( arrayLen( transports ) < variables.MAX_TRANSPORTS && isSimpleValue( t ) && reFind( "^[a-z-]{1,20}$", t ) && !arrayFind( transports, t ) ) {
					arrayAppend( transports, t );
				}
			}
		}
		var typed = trim( fieldOf( arguments.answer, "name" ) );
		var credential = {
			credentialId : credentialId,
			userId       : userId,
			publicKey    : key.spki,
			algorithm    : val( key.algorithm ),
			signCount    : counterOf( buffer ),
			transports   : transports,
			name         : len( typed ) ? left( typed, 100 ) : "Passkey",
			createdAt    : now()
		};
		variables.store.add( credential );
		return credential;
	}

	/**
	 * PublicKeyCredentialRequestOptionsJSON. With a userId only that user's passkeys
	 * are offered (re-confirming who's signed in); without one the browser offers
	 * whichever of this site's discoverable passkeys it has.
	 */
	struct function signInOptions( required struct sessionData, string userId = "" ) {
		var allowed = [];
		if ( len( arguments.userId ) ) {
			for ( var c in variables.store.listForUser( arguments.userId ) ) {
				arrayAppend( allowed, descriptor( c ) );
			}
		}
		return {
			"challenge"        : newChallenge( arguments.sessionData, "sign-in", arguments.userId ),
			"rpId"             : variables.settings.rpId,
			"timeout"          : javacast( "int", variables.settings.challengeSeconds * 1000 ),
			"userVerification" : variables.settings.userVerification,
			"allowCredentials" : allowed
		};
	}

	/**
	 * Checks a sign-in answer: { id, clientDataJSON, authenticatorData, signature, userHandle? }
	 * (base64url). Returns { userId, credentialId, userVerified, signCount, credential }.
	 * When the options were made for a userId, the passkey must be theirs.
	 * Throws Passkeys.Invalid for anything that doesn't check out.
	 */
	struct function verify( required struct sessionData, required struct answer ) {
		var held = takeChallenge( arguments.sessionData, "sign-in" );
		var credential = variables.store.findByCredentialId( encode( decodeField( arguments.answer, "id" ) ) );
		if ( isNull( credential ) ) {
			invalid( "That passkey isn't one this site knows. It may have been removed." );
		}
		var userId = toString( credential.userId );
		if ( len( held.userId ) && compare( held.userId, userId ) != 0 ) {
			invalid( "That passkey belongs to another account" );
		}
		if ( len( fieldOf( arguments.answer, "userHandle" ) ) ) {
			var handle = charsetEncode( decodeField( arguments.answer, "userHandle" ), "utf-8" );
			if ( compare( handle, userId ) != 0 ) {
				invalid( "That passkey belongs to another account" );
			}
		}
		var clientData = decodeField( arguments.answer, "clientDataJSON" );
		checkClientData( clientData, "webauthn.get", held.value );
		var authData = decodeField( arguments.answer, "authenticatorData" );
		var buffer = checkAuthData( authData );

		var signed = createObject( "java", "java.io.ByteArrayOutputStream" ).init();
		writeBytes( signed, authData );
		writeBytes( signed, sha256( clientData ) );
		var algorithm = toString( int( credential.algorithm ) );
		if ( !structKeyExists( variables.SUPPORTED, algorithm ) || !arrayFind( variables.settings.algorithms, algorithm ) ) {
			invalid( "That passkey uses a kind of key this site doesn't take" );
		}
		var check = createObject( "java", "java.security.Signature" ).getInstance( variables.SUPPORTED[ algorithm ].signature );
		check.initVerify( publicKeyOf( credential.publicKey, algorithm ) );
		check.update( signed.toByteArray() );
		var good = false;
		try {
			good = check.verify( decodeField( arguments.answer, "signature" ) );
		} catch ( any e ) {
			if ( e.type == "Passkeys.Invalid" ) {
				rethrow;
			}
			good = false;
		}
		if ( !good ) {
			invalid( "That passkey's signature doesn't check out" );
		}

		// a counter that doesn't move forward means the key was cloned; most passkeys keep 0
		var counter = counterOf( buffer );
		if ( ( counter > 0 || credential.signCount > 0 ) && counter <= credential.signCount ) {
			invalid( "That passkey looks copied. Remove it and add it again." );
		}
		var usedAt = now();
		if ( !variables.store.updateUsage( credential.credentialId, counter, usedAt ) ) {
			invalid( "That passkey looks copied. Remove it and add it again." );
		}
		credential.signCount = counter;
		credential.lastUsedAt = usedAt;
		return {
			userId       : userId,
			credentialId : credential.credentialId,
			userVerified : bitAnd( buffer.get( javacast( "int", 32 ) ), variables.FLAG_USER_VERIFIED ) > 0,
			signCount    : counter,
			credential   : credential
		};
	}

	boolean function originAllowed( required string origin ) {
		var given = lCase( arguments.origin );
		if ( arrayLen( variables.settings.origins ) ) {
			return arrayFind( variables.settings.origins, given ) > 0;
		}
		var found = reFind( "^(https?)://([^/:]+)(:[0-9]+)?$", given, 1, true );
		if ( !found.pos[ 1 ] ) {
			return false;
		}
		var scheme = mid( given, found.pos[ 2 ], found.len[ 2 ] );
		var host = mid( given, found.pos[ 3 ], found.len[ 3 ] );
		var rpId = variables.settings.rpId;
		var subdomain = variables.settings.allowSubdomains
			&& len( host ) > len( rpId ) + 1
			&& right( host, len( rpId ) + 1 ) == "." & rpId;
		if ( host != rpId && !subdomain ) {
			return false;
		}
		return scheme == "https" || host == "localhost";
	}

	private struct function descriptor( required struct credential ) {
		return { "type": "public-key", "id": arguments.credential.credentialId, "transports": arguments.credential.transports ?: [] };
	}

	private string function userIdOf( required struct user ) {
		var id = valueOf( arguments.user, "id", "" );
		if ( !isSimpleValue( id ) || !len( toString( id ) ) || len( charsetDecode( toString( id ), "utf-8" ) ) > 64 ) {
			throw( type = "Passkeys.Configuration", message = "user.id must be 1 to 64 bytes" );
		}
		return toString( id );
	}

	private string function newChallenge( required struct sessionData, required string purpose, required string userId ) {
		var bytes = createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", 32 ) ).array();
		variables.random.nextBytes( bytes );
		var value = encode( bytes );
		var key = variables.settings.sessionKey;
		var lockName = challengeLock( arguments.sessionData );
		lock name="#lockName#" type="exclusive" timeout="5" {
			var slots = arguments.sessionData[ key ] ?: {};
			if ( !isStruct( slots ) ) {
				slots = {};
			}
			slots[ arguments.purpose ] = {
				value   : value,
				purpose : arguments.purpose,
				userId  : arguments.userId,
				expires : nowMillis() + variables.settings.challengeSeconds * 1000
			};
			arguments.sessionData[ key ] = slots;
		}
		return value;
	}

	/** The session's challenge for this purpose, used up whatever happens next. */
	private struct function takeChallenge( required struct sessionData, required string purpose ) {
		var held = {};
		var key = variables.settings.sessionKey;
		var lockName = challengeLock( arguments.sessionData );
		lock name="#lockName#" type="exclusive" timeout="5" {
			var slots = arguments.sessionData[ key ] ?: {};
			if ( isStruct( slots ) ) {
				held = slots[ arguments.purpose ] ?: {};
				structDelete( slots, arguments.purpose );
				arguments.sessionData[ key ] = slots;
			}
		}
		if ( !isStruct( held ) || ( held.purpose ?: "" ) != arguments.purpose ) {
			invalid( "That answer was already used, or never asked for. Try again." );
		}
		if ( ( held.expires ?: 0 ) < nowMillis() ) {
			invalid( "That took too long. Try again." );
		}
		return held;
	}

	/** Serializes challenge reads and writes on one session struct, so a challenge can't be taken twice. */
	private string function challengeLock( required struct sessionData ) {
		return "cbpasskeys.challenge." & createObject( "java", "java.lang.System" ).identityHashCode( arguments.sessionData );
	}

	private numeric function nowMillis() {
		return createObject( "java", "java.lang.System" ).currentTimeMillis();
	}

	private void function checkClientData( required clientData, required string type, required string challenge ) {
		var parsed = {};
		try {
			parsed = deserializeJSON( charsetEncode( arguments.clientData, "utf-8" ) );
		} catch ( any e ) {
			invalid( "The browser's answer can't be read" );
		}
		if ( !isStruct( parsed ) || toString( parsed.type ?: "" ) != arguments.type ) {
			invalid( "The browser's answer is for something else" );
		}
		if ( !isSimpleValue( parsed.challenge ?: "" ) || compare( toString( parsed.challenge ?: "" ), arguments.challenge ) != 0 ) {
			invalid( "That answer is for another try. Try again." );
		}
		if ( !isSimpleValue( parsed.origin ?: "" ) || !originAllowed( parsed.origin ?: "" ) ) {
			invalid( "That passkey was used on another site" );
		}
		var crossOrigin = parsed.crossOrigin ?: false;
		if ( isBoolean( crossOrigin ) && crossOrigin ) {
			invalid( "That passkey was used inside another site's frame" );
		}
	}

	/** A ByteBuffer over authenticatorData once its site, presence and verification check out. */
	private function checkAuthData( required authData ) {
		if ( len( arguments.authData ) < 37 ) {
			invalid( "The authenticator's answer is too short" );
		}
		if ( !sameBytes( slice( arguments.authData, 0, 32 ), sha256( charsetDecode( variables.settings.rpId, "utf-8" ) ) ) ) {
			invalid( "That passkey is for another site" );
		}
		var buffer = createObject( "java", "java.nio.ByteBuffer" ).wrap( arguments.authData );
		var flags = buffer.get( javacast( "int", 32 ) );
		if ( !bitAnd( flags, variables.FLAG_USER_PRESENT ) ) {
			invalid( "The authenticator didn't confirm you were there" );
		}
		if ( variables.settings.userVerification == "required" && !bitAnd( flags, variables.FLAG_USER_VERIFIED ) ) {
			invalid( "The authenticator didn't confirm it was you" );
		}
		return buffer;
	}

	/** The authenticator's 32-bit unsigned sign counter. */
	private numeric function counterOf( required buffer ) {
		return createObject( "java", "java.lang.Integer" ).toUnsignedLong( arguments.buffer.getInt( javacast( "int", 33 ) ) );
	}

	private function publicKeyOf( required string spki, required string algorithm ) {
		var bytes = decode( arguments.spki );
		try {
			return createObject( "java", "java.security.KeyFactory" )
				.getInstance( variables.SUPPORTED[ arguments.algorithm ].key )
				.generatePublic( createObject( "java", "java.security.spec.X509EncodedKeySpec" ).init( bytes ) );
		} catch ( any e ) {
			invalid( "That passkey's key can't be read" );
		}
	}

	/** A field of the browser's answer as a string, "" when it's missing or not a simple value. */
	private string function fieldOf( required struct answer, required string name ) {
		var value = valueOf( arguments.answer, arguments.name, "" );
		return isSimpleValue( value ) ? toString( value ) : "";
	}

	private string function requireField( required struct answer, required string name ) {
		var value = valueOf( arguments.answer, arguments.name, "" );
		if ( !isSimpleValue( value ) || !len( value ) || len( value ) > 8000 ) {
			invalid( "The browser's answer is missing #arguments.name#" );
		}
		return toString( value );
	}

	private function decodeField( required struct answer, required string name ) {
		return decode( requireField( arguments.answer, arguments.name ) );
	}

	private function decode( required string value ) {
		var trimmed = reReplace( arguments.value, "=+$", "" );
		try {
			return variables.urlDecoder.decode( trimmed );
		} catch ( any e ) {
			invalid( "The browser's answer can't be read" );
		}
	}

	private string function encode( required bytes ) {
		return variables.urlEncoder.encodeToString( arguments.bytes );
	}

	private function sha256( required bytes ) {
		return createObject( "java", "java.security.MessageDigest" ).getInstance( "SHA-256" ).digest( arguments.bytes );
	}

	private function slice( required bytes, required numeric from, required numeric to ) {
		var size = arguments.to - arguments.from;
		var copy = createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", size ) ).array();
		createObject( "java", "java.lang.System" ).arraycopy( arguments.bytes, javacast( "int", arguments.from ), copy, javacast( "int", 0 ), javacast( "int", size ) );
		return copy;
	}

	private void function writeBytes( required out, required bytes ) {
		arguments.out.write( arguments.bytes, javacast( "int", 0 ), javacast( "int", len( arguments.bytes ) ) );
	}

	private boolean function sameBytes( required a, required b ) {
		return createObject( "java", "java.security.MessageDigest" ).isEqual( arguments.a, arguments.b );
	}

	/** source[key], or fallback when it's missing or null. Not `?:`, which on Adobe CF also skips 0 and false. */
	private function valueOf( required struct source, required string key, fallback = "" ) {
		if ( structKeyExists( arguments.source, arguments.key ) && !isNull( arguments.source[ arguments.key ] ) ) {
			return arguments.source[ arguments.key ];
		}
		return arguments.fallback;
	}

	private void function invalid( required string message ) {
		throw( type = "Passkeys.Invalid", message = arguments.message );
	}

}
