component {

	function configure() {
		coldbox = {
			appName                 : "cbpasskeys test harness",
			reinitPassword          : "",
			handlersIndexAutoReload : true
		};
		moduleSettings = {
			cbpasskeys : {
				rpId            : "example.com",
				rpName          : "Example",
				credentialStore : "MemoryCredentialStore@cbpasskeys"
			}
		};
	}

}
