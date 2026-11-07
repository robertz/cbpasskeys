/**
 * The README's example handler. session.user stands in for your own sign-in
 * (cbauth, cbsecurity or your own); everything else is what an app would write.
 */
component {

	property name="passkeys" inject="RelyingParty@cbpasskeys";

	function registrationOptions( event, rc, prc ) {
		if ( !structKeyExists( session, "user" ) ) {
			return refuse( event, "Sign in first", 401 );
		}
		try {
			var options = passkeys.registrationOptions(
				{ id: session.user.id, name: session.user.email, displayName: session.user.name },
				session
			);
			return event.renderData( type = "json", data = options );
		} catch ( "Passkeys.Invalid" e ) {
			return refuse( event, e.message, 400 );
		}
	}

	function register( event, rc, prc ) {
		if ( !structKeyExists( session, "user" ) ) {
			return refuse( event, "Sign in first", 401 );
		}
		try {
			var credential = passkeys.register( { id: session.user.id }, session, bodyOf( event ) );
			return event.renderData( type = "json", data = { "id": credential.credentialId, "name": credential.name } );
		} catch ( "Passkeys.Invalid" e ) {
			return refuse( event, e.message, 400 );
		}
	}

	function signInOptions( event, rc, prc ) {
		return event.renderData( type = "json", data = passkeys.signInOptions( session ) );
	}

	function signIn( event, rc, prc ) {
		var result = {};
		try {
			result = passkeys.verify( session, bodyOf( event ) );
		} catch ( "Passkeys.Invalid" e ) {
			return refuse( event, e.message, 401 );
		}
		sessionRotate();
		session.user = { id: result.userId };
		return event.renderData( type = "json", data = { "signedIn": true } );
	}

	function list( event, rc, prc ) {
		if ( !structKeyExists( session, "user" ) ) {
			return refuse( event, "Sign in first", 401 );
		}
		var shown = [];
		for ( var c in passkeys.getStore().listForUser( session.user.id ) ) {
			arrayAppend( shown, { "id": c.credentialId, "name": c.name, "createdAt": c.createdAt, "lastUsedAt": c.lastUsedAt ?: "" } );
		}
		return event.renderData( type = "json", data = shown );
	}

	function remove( event, rc, prc ) {
		if ( !structKeyExists( session, "user" ) ) {
			return refuse( event, "Sign in first", 401 );
		}
		var store = passkeys.getStore();
		var wanted = toString( bodyOf( event ).id ?: "" );
		var owned = store.listForUser( session.user.id ).some( ( c ) => compare( c.credentialId, wanted ) == 0 );
		if ( !owned ) {
			return refuse( event, "Not found", 404 );
		}
		store.remove( wanted );
		return event.renderData( type = "json", data = { "removed": true } );
	}

	private struct function bodyOf( event ) {
		var body = event.getHTTPContent( json = true );
		return isStruct( body ) ? body : {};
	}

	private function refuse( event, required string message, required numeric status ) {
		return event.renderData( type = "json", data = { "error": arguments.message }, statusCode = arguments.status );
	}

}
