<cfsetting showDebugOutput="false" requestTimeout="300">
<cfparam name="url.reporter" default="text">
<cfscript>
	testbox = new testbox.system.TestBox( directory = "tests.specs", reporter = url.reporter );
	results = testbox.run();
	result = testbox.getResult();
	if ( result.getTotalFail() || result.getTotalError() ) {
		cfheader( statusCode = 417 );
	}
	writeOutput( results );
</cfscript>
