/**
 * A passkey authenticator for specs: answers navigator.credentials.create() and
 * .get() options as a browser would (binary fields base64url), with an ES256,
 * Ed25519 or RS256 key. Registration answers carry both attestationObject (fmt
 * "none", COSE key inside) and the SPKI publicKey, so either path can be tested.
 */
component accessors="true" {

	property name="credentialId" type="string";
	property name="counter" type="numeric";
	property name="origin" type="string";

	function init( string origin = "http://localhost:5173", string rpId = "localhost", numeric algorithm = -7 ) {
		variables.algorithm = arguments.algorithm;
		var generator = "";
		if ( arguments.algorithm == -8 ) {
			generator = createObject( "java", "java.security.KeyPairGenerator" ).getInstance( "Ed25519" );
		} else if ( arguments.algorithm == -257 ) {
			generator = createObject( "java", "java.security.KeyPairGenerator" ).getInstance( "RSA" );
			generator.initialize( javacast( "int", 2048 ) );
		} else {
			generator = createObject( "java", "java.security.KeyPairGenerator" ).getInstance( "EC" );
			generator.initialize( createObject( "java", "java.security.spec.ECGenParameterSpec" ).init( "secp256r1" ) );
		}
		variables.keys = generator.generateKeyPair();
		var id = zeros( 16 );
		createObject( "java", "java.security.SecureRandom" ).init().nextBytes( id );
		variables.credentialId = encode( id );
		variables.counter = 0;
		variables.origin = arguments.origin;
		variables.rpId = arguments.rpId;
		variables.userHandle = "";
		return this;
	}

	/** The answer to registration options; `changes` overrides any of its fields and `drop` leaves fields out. */
	struct function create( required struct options, struct changes = {}, array drop = [] ) {
		var id = decode( variables.credentialId );
		variables.userHandle = arguments.options.user.id;
		var data = bytesOf( [
			sha256( charsetDecode( variables.rpId, "utf-8" ) ),
			// user present and verified, attested credential data follows
			[ 69 ],
			int32( variables.counter ),
			zeros( 16 ),
			int16( len( id ) ),
			id,
			cbor( coseKey() )
		] );
		var attestation = structNew( "ordered" );
		attestation[ "fmt" ] = "none";
		attestation[ "attStmt" ] = {};
		attestation[ "authData" ] = data;
		var answer = {
			"id"                 : variables.credentialId,
			"clientDataJSON"     : encode( charsetDecode( clientData( "webauthn.create", arguments.options.challenge ), "utf-8" ) ),
			"attestationObject"  : encode( cbor( attestation ) ),
			"authenticatorData"  : encode( data ),
			"publicKey"          : encode( viaInterface( variables.keys.getPublic(), "java.security.Key", "getEncoded" ) ),
			"publicKeyAlgorithm" : variables.algorithm,
			"transports"         : [ "internal" ],
			"name"               : "Test key"
		};
		for ( var key in arguments.changes ) {
			answer[ key ] = arguments.changes[ key ];
		}
		for ( var field in arguments.drop ) {
			structDelete( answer, field );
		}
		return answer;
	}

	/** The answer to sign-in options, signed with this key (or with `signer`, another authenticator's). */
	struct function get( required struct options, string type = "webauthn.get", signer, numeric flags = 5 ) {
		var signedBy = arguments.signer ?: this;
		variables.counter++;
		var json = charsetDecode( clientData( arguments.type, arguments.options.challenge ), "utf-8" );
		var data = bytesOf( [ sha256( charsetDecode( variables.rpId, "utf-8" ) ), [ arguments.flags ], int32( variables.counter ) ] );
		var answer = {
			"id"                : variables.credentialId,
			"clientDataJSON"    : encode( json ),
			"authenticatorData" : encode( data ),
			"signature"         : encode( signedBy.sign( bytesOf( [ data, sha256( json ) ] ) ) )
		};
		if ( len( variables.userHandle ) ) {
			answer[ "userHandle" ] = variables.userHandle;
		}
		return answer;
	}

	function sign( required bytes ) {
		var signer = createObject( "java", "java.security.Signature" ).getInstance( signatureName() );
		signer.initSign( variables.keys.getPrivate() );
		signer.update( arguments.bytes );
		return signer.sign();
	}

	function setOrigin( required string origin ) {
		variables.origin = arguments.origin;
		return this;
	}

	function setCounter( required numeric counter ) {
		variables.counter = arguments.counter;
		return this;
	}

	/** The public key as a COSE_Key map, keys as numeric strings. */
	struct function coseKey() {
		var key = variables.keys.getPublic();
		var map = structNew( "ordered" );
		if ( variables.algorithm == -8 ) {
			var spki = viaInterface( key, "java.security.Key", "getEncoded" );
			map[ "1" ] = 1;
			map[ "3" ] = -8;
			map[ "-1" ] = 6;
			map[ "-2" ] = slice( spki, len( spki ) - 32, len( spki ) );
			return map;
		}
		if ( variables.algorithm == -257 ) {
			map[ "1" ] = 3;
			map[ "3" ] = -257;
			map[ "-1" ] = unsigned( viaInterface( key, "java.security.interfaces.RSAKey", "getModulus" ), 0 );
			map[ "-2" ] = unsigned( viaInterface( key, "java.security.interfaces.RSAPublicKey", "getPublicExponent" ), 0 );
			return map;
		}
		map[ "1" ] = 2;
		map[ "3" ] = -7;
		map[ "-1" ] = 1;
		var point = viaInterface( key, "java.security.interfaces.ECPublicKey", "getW" );
		map[ "-2" ] = unsigned( point.getAffineX(), 32 );
		map[ "-3" ] = unsigned( point.getAffineY(), 32 );
		return map;
	}

	/** Minimal CBOR encoder: integers, byte strings, text, arrays, maps (numeric-string keys become integers). */
	function cbor( required value ) {
		var out = createObject( "java", "java.io.ByteArrayOutputStream" ).init();
		writeItem( out, arguments.value );
		return out.toByteArray();
	}

	private void function writeItem( required out, required value ) {
		if ( isBinary( arguments.value ) ) {
			writeHead( arguments.out, 2, len( arguments.value ) );
			writeAll( arguments.out, arguments.value );
		} else if ( isStruct( arguments.value ) ) {
			writeHead( arguments.out, 5, structCount( arguments.value ) );
			for ( var key in arguments.value ) {
				writeItem( arguments.out, reFind( "^-?[0-9]+$", key ) ? int( key ) : key );
				writeItem( arguments.out, arguments.value[ key ] );
			}
		} else if ( isArray( arguments.value ) ) {
			writeHead( arguments.out, 4, arrayLen( arguments.value ) );
			for ( var item in arguments.value ) {
				writeItem( arguments.out, item );
			}
		} else if ( isNumeric( arguments.value ) && reFind( "^-?[0-9]+$", toString( arguments.value ) ) ) {
			if ( arguments.value < 0 ) {
				writeHead( arguments.out, 1, -1 - arguments.value );
			} else {
				writeHead( arguments.out, 0, arguments.value );
			}
		} else {
			var text = charsetDecode( toString( arguments.value ), "utf-8" );
			writeHead( arguments.out, 3, len( text ) );
			writeAll( arguments.out, text );
		}
	}

	private void function writeHead( required out, required numeric major, required numeric size ) {
		var lead = arguments.major * 32;
		if ( arguments.size < 24 ) {
			arguments.out.write( javacast( "int", lead + arguments.size ) );
		} else if ( arguments.size < 256 ) {
			arguments.out.write( javacast( "int", lead + 24 ) );
			arguments.out.write( javacast( "int", arguments.size ) );
		} else if ( arguments.size < 65536 ) {
			arguments.out.write( javacast( "int", lead + 25 ) );
			writeAll( arguments.out, int16( arguments.size ) );
		} else {
			arguments.out.write( javacast( "int", lead + 26 ) );
			writeAll( arguments.out, int32( arguments.size ) );
		}
	}

	private string function signatureName() {
		if ( variables.algorithm == -8 ) {
			return "Ed25519";
		}
		return variables.algorithm == -257 ? "SHA256withRSA" : "SHA256withECDSA";
	}

	/** A BigInteger's magnitude, left-padded to `size` bytes when size > 0. */
	private function unsigned( required number, required numeric size ) {
		var raw = arguments.number.toByteArray();
		var magnitude = ceiling( arguments.number.bitLength() / 8 );
		if ( len( raw ) > magnitude ) {
			raw = slice( raw, len( raw ) - magnitude, len( raw ) );
		}
		if ( arguments.size == 0 || len( raw ) == arguments.size ) {
			return raw;
		}
		var padded = createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", arguments.size ) );
		padded.position( javacast( "int", arguments.size - len( raw ) ) );
		padded.put( raw );
		return padded.array();
	}

	private string function clientData( required string type, required string challenge ) {
		return '{"type":"#arguments.type#","challenge":"#arguments.challenge#","origin":"#variables.origin#","crossOrigin":false}';
	}

	private function bytesOf( required array parts ) {
		var out = createObject( "java", "java.io.ByteArrayOutputStream" ).init();
		for ( var part in arguments.parts ) {
			if ( isBinary( part ) ) {
				writeAll( out, part );
			} else {
				for ( var b in part ) {
					out.write( javacast( "int", b ) );
				}
			}
		}
		return out.toByteArray();
	}

	/**
	 * Calls a no-argument method through the public interface that declares it. Adobe CF
	 * reflects on the runtime class (sun.security.*), which Java 17+ modules don't open.
	 */
	private function viaInterface( required target, required string interfaceName, required string methodName ) {
		var method = createObject( "java", "java.lang.Class" ).forName( arguments.interfaceName ).getMethod( arguments.methodName, javacast( "null", "" ) );
		return method.invoke( arguments.target, javacast( "null", "" ) );
	}

	private void function writeAll( required out, required bytes ) {
		arguments.out.write( arguments.bytes, javacast( "int", 0 ), javacast( "int", len( arguments.bytes ) ) );
	}

	private function zeros( required numeric size ) {
		return createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", arguments.size ) ).array();
	}

	private function slice( required bytes, required numeric from, required numeric to ) {
		var size = arguments.to - arguments.from;
		var copy = createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", size ) ).array();
		createObject( "java", "java.lang.System" ).arraycopy( arguments.bytes, javacast( "int", arguments.from ), copy, javacast( "int", 0 ), javacast( "int", size ) );
		return copy;
	}

	private function int32( required numeric value ) {
		return createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", 4 ) ).putInt( javacast( "int", arguments.value ) ).array();
	}

	private function int16( required numeric value ) {
		return createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", 2 ) ).putShort( javacast( "short", arguments.value ) ).array();
	}

	private function sha256( required bytes ) {
		return createObject( "java", "java.security.MessageDigest" ).getInstance( "SHA-256" ).digest( arguments.bytes );
	}

	private string function encode( required bytes ) {
		return createObject( "java", "java.util.Base64" ).getUrlEncoder().withoutPadding().encodeToString( arguments.bytes );
	}

	private function decode( required string value ) {
		return createObject( "java", "java.util.Base64" ).getUrlDecoder().decode( arguments.value );
	}

}
