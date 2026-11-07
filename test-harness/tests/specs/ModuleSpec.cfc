/** The module as ColdBox loads it: its settings and WireBox mappings. */
component extends="coldbox.system.testing.BaseTestCase" appMapping="/root" {

	function beforeAll() {
		super.beforeAll();
		getController().getModuleService().registerAndActivateModule( "cbpasskeys", "moduleroot" );
	}

	function run() {

		describe( "cbpasskeys module", () => {

			it( "merges moduleSettings over its defaults", () => {
				var rp = getInstance( "RelyingParty@cbpasskeys" );
				expect( rp.getSettings().rpId ).toBe( "example.com" );
				expect( rp.getSettings().rpName ).toBe( "Example" );
				expect( rp.getSettings().challengeSeconds ).toBe( 300 );
				expect( rp.getSettings().algorithms ).toBe( [ "-7", "-8", "-257" ] );
				expect( rp.getSettings().allowSubdomains ).toBeFalse();
			} );

			it( "is a singleton built on the configured store", () => {
				var rp = getInstance( "RelyingParty@cbpasskeys" );
				expect( getInstance( "RelyingParty@cbpasskeys" ) ).toBe( rp );
				expect( getMetadata( rp.getStore() ).name ).toInclude( "MemoryCredentialStore" );
				expect( rp.getStore() ).toBe( getInstance( "MemoryCredentialStore@cbpasskeys" ) );
			} );

			it( "maps the table store with the module's store settings", () => {
				expect( getMetadata( getInstance( "TableCredentialStore@cbpasskeys" ) ).name ).toInclude( "TableCredentialStore" );
			} );

		} );

	}

}
