/** The in-memory store keeps credential ids apart by case, as the table store does. */
component extends="testbox.system.BaseSpec" {

	function run() {

		describe( "MemoryCredentialStore", () => {

			it( "tells credential ids apart by case and lists newest first", () => {
				var store = new cbpasskeys.models.MemoryCredentialStore();
				store.add( { credentialId: "abc", userId: "1", signCount: 0, name: "Lower" } );
				store.add( { credentialId: "ABC", userId: "1", signCount: 0, name: "Upper" } );
				expect( store.findByCredentialId( "abc" ).name ).toBe( "Lower" );
				expect( store.findByCredentialId( "ABC" ).name ).toBe( "Upper" );
				expect( store.listForUser( "1" ).map( ( c ) => c.name ) ).toBe( [ "Upper", "Lower" ] );
				expect( store.listForUser( "1" ).len() ).toBe( 2 );
				expect( store.remove( "abc" ) ).toBeTrue();
				expect( store.remove( "abc" ) ).toBeFalse();
				expect( isNull( store.findByCredentialId( "abc" ) ) ).toBeTrue();
			} );

		} );

	}

}
