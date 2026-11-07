/** The CBOR subset: what authenticators send, and what they mustn't. */
component extends="testbox.system.BaseSpec" {

	private function hex( required string value ) {
		return binaryDecode( arguments.value, "hex" );
	}

	function run() {

		describe( "Cbor", () => {

			beforeEach( () => {
				variables.cbor = new cbpasskeys.models.Cbor();
			} )

			it( "reads integers of every width, negative ones too", () => {
				expect( cbor.decode( hex( "00" ) ) ).toBe( 0 )
				expect( cbor.decode( hex( "17" ) ) ).toBe( 23 )
				expect( cbor.decode( hex( "1818" ) ) ).toBe( 24 )
				expect( cbor.decode( hex( "1903e8" ) ) ).toBe( 1000 )
				expect( cbor.decode( hex( "1a000f4240" ) ) ).toBe( 1000000 )
				expect( cbor.decode( hex( "20" ) ) ).toBe( -1 )
				expect( cbor.decode( hex( "26" ) ) ).toBe( -7 )
				expect( cbor.decode( hex( "390100" ) ) ).toBe( -257 )
			} )

			it( "reads byte strings, text, arrays, maps and simple values", () => {
				var bytes = cbor.decode( hex( "43010203" ) )
				expect( isBinary( bytes ) ).toBeTrue()
				expect( len( bytes ) ).toBe( 3 )
				expect( cbor.decode( hex( "646e6f6e65" ) ) ).toBe( "none" )
				expect( cbor.decode( hex( "83010203" ) ) ).toBe( [ 1, 2, 3 ] )
				var map = cbor.decode( hex( "a201022620" ) )
				expect( map[ "1" ] ).toBe( 2 )
				expect( map[ "-7" ] ).toBe( -1 )
				expect( cbor.decode( hex( "f5" ) ) ).toBeTrue()
				expect( cbor.decode( hex( "f4" ) ) ).toBeFalse()
				expect( cbor.decode( hex( "f93c00" ) ) ).toBe( 1 )
				expect( cbor.decode( hex( "c1" & "1a514b67b0" ) ) ).toBe( 1363896240 )
			} )

			it( "reads null, undefined, and half, single and double floats", () => {
				expect( cbor.decode( hex( "f6" ) ) ).toBe( "" );
				expect( cbor.decode( hex( "f7" ) ) ).toBe( "" );
				expect( cbor.decode( hex( "f93e00" ) ) ).toBe( 1.5 );
				expect( cbor.decode( hex( "f90001" ) ) * 2 ^ 24 ).toBe( 1 );
				expect( cbor.decode( hex( "fa3fc00000" ) ) ).toBe( 1.5 );
				expect( cbor.decode( hex( "fb3ff8000000000000" ) ) ).toBe( 1.5 );
			} );

			it( "refuses map keys that aren't simple, other simple values, and infinite halves", () => {
				expect( () => cbor.decode( hex( "a18000" ) ) ).toThrow( "Passkeys.Invalid", "map key" );
				expect( () => cbor.decode( hex( "e0" ) ) ).toThrow( "Passkeys.Invalid", "simple value" );
				expect( () => cbor.decode( hex( "f97c00" ) ) ).toThrow( "Passkeys.Invalid", "simple value" );
			} );

			it( "reads the item at an offset and says where the next starts", () => {
				var item = cbor.decodeAt( hex( "ff" & "a10102" & "00" ), 1 )
				expect( item.value[ "1" ] ).toBe( 2 )
				expect( item.next ).toBe( 4 )
			} )

			it( "refuses truncated, indefinite, trailing and too-deep input", () => {
				expect( () => cbor.decode( hex( "430102" ) ) ).toThrow( "Passkeys.Invalid" )
				expect( () => cbor.decode( hex( "5f" ) ) ).toThrow( "Passkeys.Invalid" )
				expect( () => cbor.decode( hex( "0000" ) ) ).toThrow( "Passkeys.Invalid" )
				expect( () => cbor.decode( hex( repeatString( "81", 40 ) & "00" ) ) ).toThrow( "Passkeys.Invalid" )
				expect( () => cbor.decode( hex( "1b0000000100000000" ) ) ).toThrow( "Passkeys.Invalid" )
			} )

		} )

	}

}
