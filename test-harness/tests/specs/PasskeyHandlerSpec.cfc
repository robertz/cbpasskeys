/** The README's handler, driven through ColdBox with the fake authenticator as the browser. */
component extends="coldbox.system.testing.BaseTestCase" appMapping="/root" {

	function beforeAll() {
		super.beforeAll();
		getController().getModuleService().registerAndActivateModule( "cbpasskeys", "moduleroot" );
	}

	private struct function call( required string action, struct body = {} ) {
		setup();
		var event = getRequestContext();
		var payload = arguments.body;
		prepareMock( event ).$( "getHTTPContent" ).$callback( ( boolean json = false ) => json ? payload : serializeJSON( payload ) );
		event = execute( event = "passkeys.#arguments.action#", renderResults = true );
		return {
			status : event.getRenderData().statusCode ?: 200,
			json   : deserializeJSON( event.getValue( "cbox_rendered_content" ) )
		};
	}

	function run() {

		describe( "Passkey handler", () => {

			beforeEach( () => {
				structDelete( session, "user" );
				structDelete( session, "passkeyChallenge" );
			} );

			it( "registers a passkey, signs in with it and refuses a replay", () => {
				var key = new tests.helpers.FakeAuthenticator( origin = "https://example.com", rpId = "example.com" );
				expect( call( "registrationOptions" ).status ).toBe( 401 );

				session.user = { id: "42", email: "alice@example.com", name: "Alice" };
				var options = call( "registrationOptions" );
				expect( options.status ).toBe( 200 );
				expect( options.json.rp.id ).toBe( "example.com" );
				var saved = call( "register", key.create( options.json ) );
				expect( saved.status ).toBe( 200 );
				expect( saved.json.id ).toBe( key.getCredentialId() );
				expect( call( "list" ).json[ 1 ].id ).toBe( key.getCredentialId() );

				structDelete( session, "user" );
				var answer = key.get( call( "signInOptions" ).json );
				var signedIn = call( "signIn", answer );
				expect( signedIn.status ).toBe( 200 );
				expect( session.user.id ).toBe( "42" );
				var replay = call( "signIn", answer );
				expect( replay.status ).toBe( 401 );
				expect( replay.json.error ).toInclude( "already used" );
			} );

			it( "removes only the signed-in user's passkeys", () => {
				var key = new tests.helpers.FakeAuthenticator( origin = "https://example.com", rpId = "example.com" );
				session.user = { id: "7", email: "bob@example.com", name: "Bob" };
				call( "register", key.create( call( "registrationOptions" ).json ) );
				session.user = { id: "8", email: "eve@example.com", name: "Eve" };
				expect( call( "remove", { id: key.getCredentialId() } ).status ).toBe( 404 );
				session.user = { id: "7", email: "bob@example.com", name: "Bob" };
				expect( call( "remove", { id: key.getCredentialId() } ).status ).toBe( 200 );
				expect( call( "list" ).json ).toBeEmpty();
			} );

		} );

	}

}
