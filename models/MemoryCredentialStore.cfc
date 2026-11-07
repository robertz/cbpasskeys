/** A CredentialStore in a struct: for tests, demos and single-process prototypes. */
component implements="CredentialStore" {

	function init() {
		// a Java map, because CFML struct keys ignore case and credential ids don't
		variables.credentials = createObject( "java", "java.util.LinkedHashMap" ).init();
		variables.lockName = "cbpasskeys.memory." & createUUID();
		return this;
	}

	function findByCredentialId( required string credentialId ) {
		lock name="#variables.lockName#" type="readonly" timeout="5" {
			var held = variables.credentials.get( arguments.credentialId );
			if ( isNull( held ) ) {
				return javacast( "null", "" );
			}
			return duplicate( held );
		}
	}

	array function listForUser( required string userId ) {
		var found = [];
		lock name="#variables.lockName#" type="readonly" timeout="5" {
			for ( var held in variables.credentials.values().toArray() ) {
				if ( compare( toString( held.userId ), arguments.userId ) == 0 ) {
					arrayPrepend( found, duplicate( held ) );
				}
			}
		}
		return found;
	}

	void function add( required struct credential ) {
		lock name="#variables.lockName#" type="exclusive" timeout="5" {
			variables.credentials.put( arguments.credential.credentialId, duplicate( arguments.credential ) );
		}
	}

	boolean function updateUsage( required string credentialId, required numeric signCount, required date lastUsedAt ) {
		lock name="#variables.lockName#" type="exclusive" timeout="5" {
			var held = variables.credentials.get( arguments.credentialId );
			if ( isNull( held ) ) {
				return false;
			}
			if ( arguments.signCount > 0 ? arguments.signCount <= held.signCount : held.signCount != 0 ) {
				return false;
			}
			held.signCount = arguments.signCount;
			held.lastUsedAt = arguments.lastUsedAt;
			return true;
		}
	}

	boolean function remove( required string credentialId ) {
		lock name="#variables.lockName#" type="exclusive" timeout="5" {
			return !isNull( variables.credentials.remove( arguments.credentialId ) );
		}
	}

}
