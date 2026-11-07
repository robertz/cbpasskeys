component {

	this.name              = "cbpasskeysHarness";
	this.sessionManagement = true;
	this.setClientCookies  = true;
	this.sessionTimeout    = createTimespan( 0, 0, 15, 0 );

	variables.harnessPath = getDirectoryFromPath( getCurrentTemplatePath() );
	variables.modulePath  = reReplace( variables.harnessPath, "test-harness[\\/]$", "" );
	this.mappings[ "/root" ]       = variables.harnessPath;
	this.mappings[ "/coldbox" ]    = variables.harnessPath & "coldbox";
	this.mappings[ "/testbox" ]    = variables.harnessPath & "testbox";
	this.mappings[ "/cbpasskeys" ] = variables.modulePath;
	this.mappings[ "/moduleroot" ] = reReplace( variables.modulePath, "cbpasskeys[\\/]$", "" );

	COLDBOX_APP_ROOT_PATH = variables.harnessPath;
	COLDBOX_APP_MAPPING   = "";
	COLDBOX_CONFIG_FILE   = "";
	COLDBOX_APP_KEY       = "";

	public boolean function onApplicationStart() {
		application.cbBootstrap = new coldbox.system.Bootstrap( COLDBOX_CONFIG_FILE, COLDBOX_APP_ROOT_PATH, COLDBOX_APP_KEY, COLDBOX_APP_MAPPING );
		application.cbBootstrap.loadColdbox();
		return true;
	}

	public boolean function onRequestStart( string targetPage ) {
		application.cbBootstrap.onRequestStart( arguments.targetPage );
		return true;
	}

}
