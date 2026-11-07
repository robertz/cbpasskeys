/**
 * cbpasskeys: WebAuthn passkeys for ColdBox, JDK crypto only.
 * Settings go in config/ColdBox.cfc under moduleSettings.cbpasskeys.
 */
component {

	this.title          = "cbpasskeys";
	this.author         = "Robert Zehnder";
	this.webURL         = "https://github.com/robertz/cbpasskeys";
	this.description    = "WebAuthn passkeys (registration and sign-in) for ColdBox with JDK crypto only.";
	this.version        = "0.1.0";
	this.modelNamespace = "cbpasskeys";
	this.cfmapping      = "cbpasskeys";
	this.autoMapModels  = false;
	this.dependencies   = [];

	function configure() {
		// every RelyingParty setting not listed here defaults in RelyingParty's DEFAULTS
		variables.settings = {
			rpId            : "localhost",
			rpName          : "",
			origins         : [],
			credentialStore : "TableCredentialStore@cbpasskeys",
			store           : { table: "passkey_credentials", datasource: "" }
		};
	}

	function onLoad() {
		var moduleSettings = wirebox.getInstance( dsl = "coldbox:moduleSettings:cbpasskeys" );
		binder
			.map( "TableCredentialStore@cbpasskeys" )
			.to( "#moduleMapping#.models.TableCredentialStore" )
			.initArg( name = "settings", value = moduleSettings.store ?: {} )
			.asSingleton();
		binder.map( "MemoryCredentialStore@cbpasskeys" ).to( "#moduleMapping#.models.MemoryCredentialStore" ).asSingleton();
		binder
			.map( "RelyingParty@cbpasskeys" )
			.to( "#moduleMapping#.models.RelyingParty" )
			.initArg( name = "settings", value = moduleSettings )
			.initArg( name = "store", ref = moduleSettings.credentialStore )
			.asSingleton();
	}

}
