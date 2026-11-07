/** The table-backed store, on in-memory Derby and, when test-harness/.env names one, on MySQL. */
component extends="testbox.system.BaseSpec" {

	variables.DERBY_TABLE = "CREATE TABLE passkey_credentials (
		credential_id VARCHAR(1400) NOT NULL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, public_key VARCHAR(2048) NOT NULL,
		algorithm INTEGER NOT NULL, sign_count BIGINT NOT NULL, transports VARCHAR(255), name VARCHAR(100) NOT NULL,
		created_at TIMESTAMP NOT NULL, last_used_at TIMESTAMP )";

	private array function targets() {
		var found = [ { name: "Derby", datasource: "cbpasskeys_derby", unicodeNames: false, ddl: variables.DERBY_TABLE } ];
		var known = getApplicationMetadata().datasources ?: {};
		if ( structKeyExists( known, "cbpasskeys_mysql" ) ) {
			arrayAppend( found, { name: "MySQL", datasource: "cbpasskeys_mysql", unicodeNames: true, ddl: fileRead( expandPath( "/cbpasskeys/sql/mysql.sql" ) ) } );
		}
		return found;
	}

	private boolean function isLucee() {
		return server.coldfusion.productName contains "Lucee";
	}

	function beforeAll() {
		for ( var target in targets() ) {
			try {
				queryExecute( "DROP TABLE passkey_credentials", [], { datasource: target.datasource } );
			} catch ( any e ) {
			}
			queryExecute( target.ddl, [], { datasource: target.datasource } );
		}
	}

	function run() {
		for ( var target in targets() ) {
			suiteFor( target );
		}
		describe( "TableCredentialStore settings", () => {
			it( "refuses a table name that isn't a plain identifier", () => {
				expect( () => new cbpasskeys.models.TableCredentialStore( { table: "x; DROP TABLE y" } ) ).toThrow( "Passkeys.Configuration" );
			} );
		} );
	}

	private function suiteFor( required struct target ) {
		var t = arguments.target;

		describe( "TableCredentialStore on #t.name#", () => {

			beforeEach( () => {
				queryExecute( "DELETE FROM passkey_credentials", [], { datasource: t.datasource } );
				variables.store = new cbpasskeys.models.TableCredentialStore( { datasource: t.datasource, unicodeNames: t.unicodeNames } );
			} );

			it( "adds, finds, lists newest first, updates and removes", () => {
				store.add( { credentialId: "a", userId: 7, publicKey: "k1", algorithm: -7, signCount: 0, transports: [ "usb", "nfc" ], name: "Key A", createdAt: dateAdd( "n", -5, now() ) } );
				store.add( { credentialId: "b", userId: 7, publicKey: "k2", algorithm: -8, signCount: 0, transports: [], name: "Key B" } );
				var found = store.findByCredentialId( "a" );
				expect( found.userId ).toBe( "7" );
				expect( found.algorithm ).toBe( -7 );
				expect( found.transports ).toBe( [ "usb", "nfc" ] );
				expect( isNull( found.lastUsedAt ) ).toBeTrue();
				expect( store.listForUser( "7" ).map( ( c ) => c.credentialId ) ).toBe( [ "b", "a" ] );
				expect( store.listForUser( "8" ) ).toBeEmpty();

				expect( store.updateUsage( "a", 12, now() ) ).toBeTrue();
				found = store.findByCredentialId( "a" );
				expect( found.signCount ).toBe( 12 );
				expect( isDate( found.lastUsedAt ) ).toBeTrue();

				expect( store.remove( "a" ) ).toBeTrue();
				expect( store.remove( "a" ) ).toBeFalse();
				expect( isNull( store.findByCredentialId( "a" ) ) ).toBeTrue();
			} );

			// Adobe CF's generic JDBC path reports 1 for an UPDATE that matched no rows on Derby
			it( title = "saves a counter only while it moves forward, and says whether it saved", skip = t.name == "Derby" && !isLucee(), body = () => {
				store.add( { credentialId: "a", userId: 7, publicKey: "k1", algorithm: -7, signCount: 0, transports: [], name: "Key A" } );
				store.add( { credentialId: "b", userId: 7, publicKey: "k2", algorithm: -7, signCount: 0, transports: [], name: "Key B" } );
				expect( store.updateUsage( "a", 12, now() ) ).toBeTrue();
				expect( store.updateUsage( "a", 12, now() ) ).toBeFalse();
				expect( store.updateUsage( "a", 3, now() ) ).toBeFalse();
				expect( store.updateUsage( "a", 0, now() ) ).toBeFalse();
				expect( store.findByCredentialId( "a" ).signCount ).toBe( 12 );
				expect( store.updateUsage( "b", 0, now() ) ).toBeTrue();
				expect( store.updateUsage( "b", 0, now() ) ).toBeTrue();
				expect( store.updateUsage( "missing", 1, now() ) ).toBeFalse();
			} );

			it( "tells credential ids apart by case", () => {
				store.add( { credentialId: "abc", userId: 1, publicKey: "k1", algorithm: -7, signCount: 0, transports: [], name: "Lower" } );
				store.add( { credentialId: "ABC", userId: 2, publicKey: "k2", algorithm: -7, signCount: 0, transports: [], name: "Upper" } );
				expect( store.findByCredentialId( "abc" ).name ).toBe( "Lower" );
				expect( store.findByCredentialId( "ABC" ).name ).toBe( "Upper" );
			} );

			it( "backs a full registration and sign-in", () => {
				var rp = new cbpasskeys.models.RelyingParty( { rpId: "localhost" }, store );
				var key = new tests.helpers.FakeAuthenticator( algorithm = -257 );
				var sessionData = {};
				var options = rp.registrationOptions( { id: "u-1", name: "alice" }, sessionData );
				rp.register( { id: "u-1" }, sessionData, key.create( options ) );
				var result = rp.verify( sessionData, key.get( rp.signInOptions( sessionData ) ) );
				expect( result.userId ).toBe( "u-1" );
				expect( store.findByCredentialId( key.getCredentialId() ).signCount ).toBe( 1 );
			} );

			it( "keeps non-ASCII passkey names", () => {
				store.add( { credentialId: "n", userId: 1, publicKey: "k", algorithm: -7, signCount: 0, transports: [], name: "Téléphone ✓" } );
				expect( store.findByCredentialId( "n" ).name ).toBe( "Téléphone ✓" );
			} );

		} );
	}

}
