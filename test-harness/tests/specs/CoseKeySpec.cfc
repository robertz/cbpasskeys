/** COSE keys that must be refused before any signature is checked. */
component extends="testbox.system.BaseSpec" {

	private function bytes( required numeric size ) {
		return createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", arguments.size ) ).array();
	}

	private function refused( required struct cose, required string message ) {
		var key = arguments.cose;
		var expected = arguments.message;
		expect( () => new cbpasskeys.models.CoseKey().toSpki( key ) ).toThrow( "Passkeys.Invalid", expected );
	}

	function run() {

		describe( "CoseKey", () => {

			it( "refuses a key without its type or algorithm", () => {
				refused( {}, "missing its type" );
				refused( { "1": 2 }, "missing its type" );
			} );

			it( "refuses the wrong curve for ES256 and Ed25519", () => {
				refused( { "1": 2, "3": -7, "-1": 2 }, "isn't P-256" );
				refused( { "1": 1, "3": -8, "-1": 5 }, "isn't Ed25519" );
			} );

			it( "refuses an RSA key without its modulus or exponent", () => {
				refused( { "1": 3, "3": -257 }, "RSA key is incomplete" );
				refused( { "1": 3, "3": -257, "-1": bytes( 256 ) }, "RSA key is incomplete" );
			} );

			it( "refuses a key type that doesn't go with its algorithm", () => {
				refused( { "1": 1, "3": -7 }, "kind of key" );
				refused( { "1": 2, "3": -35 }, "kind of key" );
			} );

			it( "refuses coordinates of the wrong size or type", () => {
				refused( { "1": 2, "3": -7, "-1": 1, "-2": bytes( 31 ), "-3": bytes( 32 ) }, "malformed" );
				refused( { "1": 2, "3": -7, "-1": 1, "-2": bytes( 32 ), "-3": "not bytes" }, "malformed" );
				refused( { "1": 1, "3": -8, "-1": 6, "-2": bytes( 33 ) }, "malformed" );
			} );

		} );

	}

}
