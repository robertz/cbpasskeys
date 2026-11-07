component {

	this.name              = "cbpasskeysTests" & hash( getCurrentTemplatePath() );
	this.sessionManagement = true;
	this.sessionTimeout    = createTimespan( 0, 0, 15, 0 );

	variables.testsPath   = getDirectoryFromPath( getCurrentTemplatePath() );
	variables.harnessPath = reReplace( variables.testsPath, "tests[\\/]$", "" );
	variables.modulePath  = reReplace( variables.harnessPath, "test-harness[\\/]$", "" );
	this.mappings[ "/tests" ]      = variables.testsPath;
	this.mappings[ "/root" ]       = variables.harnessPath;
	this.mappings[ "/coldbox" ]    = variables.harnessPath & "coldbox";
	this.mappings[ "/testbox" ]    = variables.harnessPath & "testbox";
	this.mappings[ "/cbpasskeys" ] = variables.modulePath;
	this.mappings[ "/moduleroot" ] = reReplace( variables.modulePath, "cbpasskeys[\\/]$", "" );

	variables.derbyUrl = "jdbc:derby:memory:cbpasskeys;create=true";
	if ( server.coldfusion.productName contains "Lucee" ) {
		this.datasources[ "cbpasskeys_derby" ] = { class: "org.apache.derby.iapi.jdbc.AutoloadedDriver", connectionString: variables.derbyUrl };
	} else {
		this.datasources[ "cbpasskeys_derby" ] = { driver: "other", class: "org.apache.derby.iapi.jdbc.AutoloadedDriver", url: variables.derbyUrl };
	}

	// an optional MySQL datasource from test-harness/.env, so the table store runs on a real driver too
	variables.envFile = variables.harnessPath & ".env";
	if ( fileExists( variables.envFile ) ) {
		variables.env = {};
		for ( variables.line in listToArray( fileRead( variables.envFile ), chr( 10 ) ) ) {
			if ( find( "=", variables.line ) ) {
				variables.env[ trim( listFirst( variables.line, "=" ) ) ] = trim( listRest( variables.line, "=" ) );
			}
		}
		if ( structKeyExists( variables.env, "CBPASSKEYS_MYSQL_URL" ) ) {
			variables.mysql = {
				class    : "com.mysql.cj.jdbc.Driver",
				username : variables.env.CBPASSKEYS_MYSQL_USER,
				password : variables.env.CBPASSKEYS_MYSQL_PASSWORD
			};
			if ( server.coldfusion.productName contains "Lucee" ) {
				variables.mysql.connectionString = variables.env.CBPASSKEYS_MYSQL_URL;
			} else {
				variables.mysql.driver = "other";
				variables.mysql.url = variables.env.CBPASSKEYS_MYSQL_URL;
			}
			this.datasources[ "cbpasskeys_mysql" ] = variables.mysql;
		}
	}

	public void function onRequestEnd() {
		structDelete( application, "cbController" );
		structDelete( application, "wirebox" );
	}

}
