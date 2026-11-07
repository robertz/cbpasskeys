/** The options must reach the browser as JSON with the right types, whatever the engine's serializer does. */
component extends="testbox.system.BaseSpec" {

	function run() {

		describe( "Options as JSON", () => {

			it( "keeps numeric-looking names as strings and keeps key case", () => {
				var rp = new cbpasskeys.models.RelyingParty( { rpId: "localhost", rpName: "2024" }, new cbpasskeys.models.MemoryCredentialStore() );
				var json = serializeJSON( rp.registrationOptions( { id: 1001, name: "1001", displayName: "1001" }, {} ) );
				expect( json ).toInclude( '"pubKeyCredParams":' );
				expect( json ).toInclude( '"name":"1001"' );
				expect( json ).toInclude( '"displayName":"1001"' );
				expect( json ).toInclude( '"name":"2024"' );
				expect( json ).toInclude( '"requireResidentKey":true' );
				expect( json ).toInclude( '"timeout":300000' );
				expect( json ).toInclude( '"alg":-7' );
				expect( json ).toInclude( '"excludeCredentials":[]' );
			} );

			it( "serializes sign-in options with an empty allowCredentials array", () => {
				var rp = new cbpasskeys.models.RelyingParty( { rpId: "localhost" }, new cbpasskeys.models.MemoryCredentialStore() );
				var json = serializeJSON( rp.signInOptions( {} ) );
				expect( json ).toInclude( '"allowCredentials":[]' );
				expect( json ).toInclude( '"rpId":"localhost"' );
			} );

		} );

	}

}
