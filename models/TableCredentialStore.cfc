/**
 * A CredentialStore over one table (see sql/ for its shape). Plain parameterized
 * SQL with no engine-specific functions, so it runs on MSSQL, MySQL, PostgreSQL,
 * Derby and the like.
 *
 *   new cbpasskeys.models.TableCredentialStore( { datasource: "app", table: "passkey_credentials" } )
 */
component implements="CredentialStore" {

	variables.COLUMNS = "credential_id, user_id, public_key, algorithm, sign_count, transports, name, created_at, last_used_at";

	/**
	 * settings: { table = "passkey_credentials", datasource = the application's default,
	 * unicodeNames = true }. unicodeNames binds the passkey name as nvarchar, which MSSQL
	 * needs to keep non-ASCII names; turn it off for drivers without national types (Derby).
	 */
	function init( struct settings = {} ) {
		variables.table = arguments.settings.table ?: "passkey_credentials";
		var unicodeNames = structKeyExists( arguments.settings, "unicodeNames" ) ? arguments.settings.unicodeNames : true;
		variables.nameType = unicodeNames ? "cf_sql_nvarchar" : "cf_sql_varchar";
		if ( !reFind( "^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$", variables.table ) ) {
			throw( type = "Passkeys.Configuration", message = "The passkey table name '#variables.table#' isn't a plain identifier" );
		}
		variables.options = {};
		if ( !isNull( arguments.settings.datasource ) && ( !isSimpleValue( arguments.settings.datasource ) || len( arguments.settings.datasource ) ) ) {
			variables.options.datasource = arguments.settings.datasource;
		}
		return this;
	}

	function findByCredentialId( required string credentialId ) {
		var rows = run(
			"SELECT #variables.COLUMNS# FROM #variables.table# WHERE credential_id = ?",
			[ { value: arguments.credentialId, cfsqltype: "cf_sql_varchar" } ]
		);
		if ( !rows.recordCount ) {
			return javacast( "null", "" );
		}
		return toCredential( rows, 1 );
	}

	array function listForUser( required string userId ) {
		var rows = run(
			"SELECT #variables.COLUMNS# FROM #variables.table# WHERE user_id = ? ORDER BY created_at DESC",
			[ { value: arguments.userId, cfsqltype: "cf_sql_varchar" } ]
		);
		var found = [];
		for ( var i = 1; i <= rows.recordCount; i++ ) {
			arrayAppend( found, toCredential( rows, i ) );
		}
		return found;
	}

	void function add( required struct credential ) {
		var c = arguments.credential;
		queryExecute(
			"INSERT INTO #variables.table# ( #variables.COLUMNS# ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ? )",
			[
				{ value: c.credentialId, cfsqltype: "cf_sql_varchar" },
				{ value: toString( c.userId ), cfsqltype: "cf_sql_varchar" },
				{ value: c.publicKey, cfsqltype: "cf_sql_varchar" },
				{ value: c.algorithm, cfsqltype: "cf_sql_integer" },
				{ value: c.signCount, cfsqltype: "cf_sql_bigint" },
				{ value: arrayToList( c.transports ?: [] ), cfsqltype: "cf_sql_varchar" },
				{ value: c.name ?: "Passkey", cfsqltype: variables.nameType },
				{ value: c.createdAt ?: now(), cfsqltype: "cf_sql_timestamp" },
				{ value: "", cfsqltype: "cf_sql_timestamp", null: isNull( c.lastUsedAt ) }
			],
			variables.options
		);
	}

	boolean function updateUsage( required string credentialId, required numeric signCount, required date lastUsedAt ) {
		var params = [
			{ value: arguments.signCount, cfsqltype: "cf_sql_bigint" },
			{ value: arguments.lastUsedAt, cfsqltype: "cf_sql_timestamp" },
			{ value: arguments.credentialId, cfsqltype: "cf_sql_varchar" }
		];
		var guard = "sign_count = 0";
		if ( arguments.signCount > 0 ) {
			guard = "sign_count < ?";
			arrayAppend( params, { value: arguments.signCount, cfsqltype: "cf_sql_bigint" } );
		}
		return changed( "UPDATE #variables.table# SET sign_count = ?, last_used_at = ? WHERE credential_id = ? AND #guard#", params );
	}

	boolean function remove( required string credentialId ) {
		return changed(
			"DELETE FROM #variables.table# WHERE credential_id = ?",
			[ { value: arguments.credentialId, cfsqltype: "cf_sql_varchar" } ]
		);
	}

	private function run( required string sql, required array params ) {
		return queryExecute( arguments.sql, arguments.params, variables.options );
	}

	/** Runs an UPDATE or DELETE; whether it touched a row. */
	private boolean function changed( required string sql, required array params ) {
		var options = duplicate( variables.options );
		options.result = "local.outcome";
		var outcome = {};
		queryExecute( arguments.sql, arguments.params, options );
		return val( outcome.recordCount ?: 0 ) > 0;
	}

	private struct function toCredential( required query rows, required numeric row ) {
		var r = arguments.row;
		var lastUsed = arguments.rows.last_used_at[ r ];
		return {
			credentialId : arguments.rows.credential_id[ r ],
			userId       : toString( arguments.rows.user_id[ r ] ),
			publicKey    : arguments.rows.public_key[ r ],
			algorithm    : val( arguments.rows.algorithm[ r ] ),
			signCount    : val( arguments.rows.sign_count[ r ] ),
			transports   : listToArray( arguments.rows.transports[ r ] ),
			name         : arguments.rows.name[ r ],
			createdAt    : arguments.rows.created_at[ r ],
			lastUsedAt   : isDate( lastUsed ) ? lastUsed : javacast( "null", "" )
		};
	}

}
