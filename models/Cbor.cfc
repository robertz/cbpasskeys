/**
 * The slice of CBOR (RFC 8949) WebAuthn needs: attestationObject and COSE keys.
 * Definite lengths only, as CTAP2 requires. Byte strings come back as byte[],
 * map keys as strings ("1", "-2", "fmt").
 */
component {

	variables.MAX_DEPTH = 16;

	function decode( required bytes ) {
		var item = decodeAt( arguments.bytes, 0 );
		if ( item.next != len( arguments.bytes ) ) {
			invalid( "Unexpected bytes after the CBOR item" );
		}
		return item.value;
	}

	/** { value, next }: the item that starts at `offset`, and where the one after it starts. */
	struct function decodeAt( required bytes, required numeric offset ) {
		var buffer = createObject( "java", "java.nio.ByteBuffer" ).wrap( arguments.bytes );
		return readItem( buffer, arguments.offset, 0 );
	}

	private struct function readItem( required buffer, required numeric pos, required numeric depth ) {
		if ( arguments.depth > variables.MAX_DEPTH ) {
			invalid( "CBOR nested too deeply" );
		}
		var initial = readByte( arguments.buffer, arguments.pos );
		var major = bitSHRN( initial, 5 );
		var info = bitAnd( initial, 31 );
		var cursor = arguments.pos + 1;

		if ( major == 7 ) {
			return readSimple( arguments.buffer, cursor, info );
		}

		var head = readLength( arguments.buffer, cursor, info );
		var size = head.value;
		cursor = head.next;

		switch ( major ) {
			case 0:
				return { value: size, next: cursor };
			case 1:
				return { value: -1 - size, next: cursor };
			case 2:
				return { value: readBytes( arguments.buffer, cursor, size ), next: cursor + size };
			case 3:
				return { value: charsetEncode( readBytes( arguments.buffer, cursor, size ), "utf-8" ), next: cursor + size };
			case 4:
				var list = [];
				for ( var i = 1; i <= size; i++ ) {
					var entry = readItem( arguments.buffer, cursor, arguments.depth + 1 );
					arrayAppend( list, entry.value );
					cursor = entry.next;
				}
				return { value: list, next: cursor };
			case 5:
				var map = structNew( "ordered" );
				for ( var j = 1; j <= size; j++ ) {
					var key = readItem( arguments.buffer, cursor, arguments.depth + 1 );
					if ( !isSimpleValue( key.value ) ) {
						invalid( "CBOR map key isn't a number or text" );
					}
					var item = readItem( arguments.buffer, key.next, arguments.depth + 1 );
					map[ toString( key.value ) ] = item.value;
					cursor = item.next;
				}
				return { value: map, next: cursor };
			default:
				// tag 6: the tagged item stands for itself here
				return readItem( arguments.buffer, cursor, arguments.depth + 1 );
		}
	}

	private struct function readLength( required buffer, required numeric pos, required numeric info ) {
		if ( arguments.info < 24 ) {
			return { value: arguments.info, next: arguments.pos };
		}
		var widths = { "24": 1, "25": 2, "26": 4, "27": 8 };
		var width = widths[ toString( arguments.info ) ] ?: 0;
		if ( !width ) {
			invalid( "Indefinite or reserved CBOR length" );
		}
		need( arguments.buffer, arguments.pos, width );
		var value = 0;
		for ( var i = 0; i < width; i++ ) {
			value = value * 256 + readByte( arguments.buffer, arguments.pos + i );
		}
		if ( value > 2147483647 ) {
			invalid( "CBOR value too large" );
		}
		return { value: value, next: arguments.pos + width };
	}

	private struct function readSimple( required buffer, required numeric pos, required numeric info ) {
		switch ( arguments.info ) {
			case 20:
				return { value: false, next: arguments.pos };
			case 21:
				return { value: true, next: arguments.pos };
			case 22:
			case 23:
				return { value: "", next: arguments.pos };
			case 25:
				need( arguments.buffer, arguments.pos, 2 );
				return { value: halfFloat( arguments.buffer.getShort( javacast( "int", arguments.pos ) ) ), next: arguments.pos + 2 };
			case 26:
				need( arguments.buffer, arguments.pos, 4 );
				return { value: arguments.buffer.getFloat( javacast( "int", arguments.pos ) ), next: arguments.pos + 4 };
			case 27:
				need( arguments.buffer, arguments.pos, 8 );
				return { value: arguments.buffer.getDouble( javacast( "int", arguments.pos ) ), next: arguments.pos + 8 };
			default:
				invalid( "Unsupported CBOR simple value" );
		}
	}

	/** IEEE 754 half precision; Float.float16ToFloat needs Java 20. */
	private numeric function halfFloat( required numeric bits ) {
		var raw = bitAnd( arguments.bits, 65535 );
		var sign = bitAnd( raw, 32768 ) ? -1 : 1;
		var exponent = bitAnd( bitSHRN( raw, 10 ), 31 );
		var fraction = bitAnd( raw, 1023 );
		if ( exponent == 0 ) {
			return sign * fraction * 2 ^ -24;
		}
		if ( exponent == 31 ) {
			invalid( "Unsupported CBOR simple value" );
		}
		return sign * ( 1 + fraction / 1024 ) * 2 ^ ( exponent - 15 );
	}

	private numeric function readByte( required buffer, required numeric pos ) {
		need( arguments.buffer, arguments.pos, 1 );
		return bitAnd( arguments.buffer.get( javacast( "int", arguments.pos ) ), 255 );
	}

	private function readBytes( required buffer, required numeric pos, required numeric size ) {
		need( arguments.buffer, arguments.pos, arguments.size );
		var copy = createObject( "java", "java.nio.ByteBuffer" ).allocate( javacast( "int", arguments.size ) ).array();
		createObject( "java", "java.lang.System" ).arraycopy( arguments.buffer.array(), javacast( "int", arguments.pos ), copy, javacast( "int", 0 ), javacast( "int", arguments.size ) );
		return copy;
	}

	private void function need( required buffer, required numeric pos, required numeric size ) {
		if ( arguments.pos + arguments.size > arguments.buffer.capacity() ) {
			invalid( "CBOR item runs past the end" );
		}
	}

	private void function invalid( required string message ) {
		throw( type = "Passkeys.Invalid", message = arguments.message );
	}

}
