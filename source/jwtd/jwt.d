module jwtd.jwt;

import std.json;
import std.base64;
import std.algorithm;
import std.array : split;

private alias Base64URLNoPadding = Base64Impl!('-', '_', Base64.NoPadding);

version(UseOpenSSL) {
	public import jwtd.jwt_openssl;
}
version(UseBotan) {
	public import jwtd.jwt_botan;
}
version(UsePhobos) {
	public import jwtd.jwt_phobos;
}

enum JWTAlgorithm : string {
	NONE  = "none",
	HS256 = "HS256",
	HS384 = "HS384",
	HS512 = "HS512",
	RS256 = "RS256",
	RS384 = "RS384",
	RS512 = "RS512",
	ES256 = "ES256",
	ES384 = "ES384",
	ES512 = "ES512"
}

class SignException : Exception {
	this(string s) { super(s); }
}

class VerifyException : Exception {
	this(string s) { super(s); }
}

/**
  simple version that accepts only strings as values for payload and header fields
*/
string encode(string[string] payload, string key, JWTAlgorithm algo = JWTAlgorithm.HS256, string[string] header_fields = null) {
	JSONValue jsonHeader = header_fields;
	JSONValue jsonPayload = payload;

	return encode(jsonPayload, key, algo, jsonHeader);
}

/**
  full version that accepts JSONValue tree as payload and header fields
*/
string encode(ref JSONValue payload, string key, JWTAlgorithm algo = JWTAlgorithm.HS256, JSONValue header_fields = null) {
	return encode(cast(ubyte[])payload.toString(), key, algo, header_fields);
}

/**
  full version that accepts ubyte[] as payload and JSONValue tree as header fields
*/
string encode(in ubyte[] payload, string key, JWTAlgorithm algo = JWTAlgorithm.HS256, JSONValue header_fields = null) {
	import std.functional : memoize;

	auto getEncodedHeader(JWTAlgorithm algo, JSONValue fields) {
		if(fields.type == JSON_TYPE.NULL)
			fields = (JSONValue[string]).init;
		fields.object["alg"] = cast(string)algo;
		fields.object["typ"] = "JWT";

		return Base64URLNoPadding.encode(cast(ubyte[])fields.toString()).idup;
	}

	string encodedHeader = memoize!(getEncodedHeader, 64)(algo, header_fields);
	string encodedPayload = Base64URLNoPadding.encode(payload);

	string signingInput = encodedHeader ~ "." ~ encodedPayload;
	string signature = Base64URLNoPadding.encode(cast(ubyte[])sign(signingInput, key, algo));

	return signingInput ~ "." ~ signature;
}

unittest {
    import jwtd.test;

	// Code coverage for when header_fields is NULL type
	auto header_fields = JSONValue();
	assert(header_fields.type == JSON_TYPE.NULL);
    auto payload = JSONValue([ "a" : "b" ]);
	encode(payload, public256, JWTAlgorithm.HS256, header_fields);
}

/**
  simple version that knows which key was used to encode the token
*/
JSONValue decode(string token, string key) {
	return decode(token, (ref _) => key);
}

/**
  full version where the key is provided after decoding the JOSE header
*/
JSONValue decode(string token, string delegate(ref JSONValue jose) lazyKey) {
	import std.algorithm : count;
	import std.conv : to;
	import std.uni : toUpper;

	if(count(token, ".") != 2)
		throw new VerifyException("Token is incorrect.");

	string[] tokenParts = split(token, ".");

	JSONValue header;
	try {
		header = parseJSON(urlsafeB64Decode(tokenParts[0]));
	} catch(Exception e) {
		throw new VerifyException("Header is incorrect.");
	}

	JWTAlgorithm alg;
	try {
		// toUpper for none
		alg = to!(JWTAlgorithm)(toUpper(header["alg"].str()));
	} catch(Exception e) {
		throw new VerifyException("Algorithm is incorrect.");
	}

	if (auto typ = ("typ" in header)) {
		string typ_str = typ.str();
		if(typ_str && typ_str != "JWT")
			throw new VerifyException("Type is incorrect.");
	}

	const key = lazyKey(header);
	if(!verifySignature(urlsafeB64Decode(tokenParts[2]), tokenParts[0]~"."~tokenParts[1], key, alg))
		throw new VerifyException("Signature is incorrect.");

	JSONValue payload;

	try {
		payload = parseJSON(urlsafeB64Decode(tokenParts[1]));
	} catch(JSONException e) {
		// Code coverage has to miss this line because the signature test above throws before this does
		throw new VerifyException("Payload JSON is incorrect.");
	}

	return payload;
}

unittest {
    import jwtd.test;
    import std.traits : EnumMembers;

    struct Keys {
        string priv;
        string pub;

        this (string priv, string pub = null) {
            this.priv = priv;
            this.pub = (pub ? pub : priv);
        }
    }

    auto commonAlgos = [
        JWTAlgorithm.NONE  : Keys(),
        JWTAlgorithm.HS256 : Keys("my key"),
        JWTAlgorithm.HS384 : Keys("his key"),
        JWTAlgorithm.HS512 : Keys("her key"),
    ];

    version (UseOpenSSL) {
        Keys[JWTAlgorithm] specialAlgos = [
            JWTAlgorithm.RS256 : Keys(private256, public256),
            // TODO: Find key pairs for RS384 and RS512
            // JWTAlgorithm.RS384 : Keys(private384, public384),
            // JWTAlgorithm.RS512 : Keys(private512, public512),
            JWTAlgorithm.ES256 : Keys(es256_private, es256_public),
            JWTAlgorithm.ES384 : Keys(es384_private, es384_public),
            JWTAlgorithm.ES512 : Keys(es512_private, es512_public),
        ];
    }

    version (UseBotan) {
        Keys[JWTAlgorithm] specialAlgos = [
            JWTAlgorithm.RS256 : Keys(private256, public256),
            // TODO: Find key pairs for the following
            // JWTAlgorithm.RS384 : Keys(private384, public384),
            // JWTAlgorithm.RS512 : Keys(private512, public512),
            // JWTAlgorithm.ES256 : Keys(es256_private, es256_public),
            // JWTAlgorithm.ES384 : Keys(es384_private, es384_public),
            // JWTAlgorithm.ES512 : Keys(es512_private, es512_public),
        ];
    }

    else {
    }

    version (UsePhobos) {
        Keys[JWTAlgorithm] specialAlgos;
    }

    void testWith(Keys[JWTAlgorithm] keys) {
        foreach (algo, k; keys) {
            auto payload = JSONValue([ "claim" : "value" ]);
            const encoded = encode(payload, k.priv, algo);
            const decoded = decode(encoded, k.pub);
            assert(decoded == payload);
        }
    }

    testWith(commonAlgos);
    testWith(specialAlgos);
}

version (unittest) {
	string corruptEncodedString(size_t part, string field, string badValue) {
		import std.conv : text;

		string encoded = encode([ "my" : "payload" ], "key");
		string[] tokenParts = split(encoded, ".");
		auto jsonValue = parseJSON(urlsafeB64Decode(tokenParts[part]));
		jsonValue[field] = badValue;
		tokenParts[part] = urlsafeB64Encode(jsonValue.toString());
		return text(tokenParts.joiner("."));
	}
}

unittest {
	import std.exception : assertThrown;

    // decode() must not accept invalid tokens

    // Must have 2 dots
	assertThrown!VerifyException(decode("nodot", "key"));
	assertThrown!VerifyException(decode("one.dot", "key"));
	assertThrown!VerifyException(decode("thr.e.e.dots", "key"));

    // Must have valid header
 	assertThrown!VerifyException(decode("corrupt.encoding.blah", "key"));

    // Must be a known algorithm
	assertThrown!VerifyException(decode(corruptEncodedString(0, "alg", "bogus_alg"), "key"));

    // Must be JWT type
	assertThrown!VerifyException(decode(corruptEncodedString(0, "typ", "JWX"), "key"));

    // Must have valid signature
	string encoded = encode([ "my" : "payload" ], "key");
	assertThrown!VerifyException(decode(encoded[0..$-1], "key"));
}

bool verify(string token, string key) {
	import std.algorithm : count;
	import std.conv : to;
	import std.uni : toUpper;

	if(count(token, ".") != 2)
		throw new VerifyException("Token is incorrect.");

	string[] tokenParts = split(token, ".");

	string decHeader = urlsafeB64Decode(tokenParts[0]);
	JSONValue header = parseJSON(decHeader);

	JWTAlgorithm alg;
	try {
		// toUpper for none
		alg = to!(JWTAlgorithm)(toUpper(header["alg"].str()));
	} catch(Exception e) {
		throw new VerifyException("Algorithm is incorrect.");
	}

	if (auto typ = ("typ" in header)) {
		string typ_str = typ.str();
		if(typ_str && typ_str != "JWT")
			throw new VerifyException("Type is incorrect.");
	}

	return verifySignature(urlsafeB64Decode(tokenParts[2]), tokenParts[0]~"."~tokenParts[1], key, alg);
}

unittest {
    // verify() must not accept invalid tokens

	import std.exception : assertThrown;

    // Must have 2 dots
	assertThrown!VerifyException(verify("nodot", "key"));
	assertThrown!VerifyException(verify("one.dot", "key"));
	assertThrown!VerifyException(verify("thr.e.e.dots", "key"));

    // Must have valid algorithm and type
	assertThrown!VerifyException(verify(corruptEncodedString(0, "alg", "bogus_alg"), "key"));
	assertThrown!VerifyException(verify(corruptEncodedString(0, "typ", "JWX"), "key"));
}

/**
 * Encode a string with URL-safe Base64.
 */
string urlsafeB64Encode(string inp) pure nothrow {
	return Base64URLNoPadding.encode(cast(ubyte[])inp);
}

/**
 * Decode a string with URL-safe Base64.
 */
string urlsafeB64Decode(string inp) pure {
	return cast(string)Base64URLNoPadding.decode(inp);
}

unittest {
    import jwtd.test;

	string hs_secret = "secret";

	// none

	string noneToken = encode(["language": "D"], "", JWTAlgorithm.NONE);
	assert(noneToken == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsYW5ndWFnZSI6IkQifQ.");
	assert(verify(noneToken, ""));
	assert(!verify(noneToken, "somesecret"));

	// hs256

	string hs256Token = encode(["language": "D"], hs_secret, JWTAlgorithm.HS256);
	assert(hs256Token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYW5ndWFnZSI6IkQifQ.utQLevAUK97y-e6B3-EnSofvTNAfSXNuSbu4moAh-hY");
	assert(verify(hs256Token, hs_secret));

	// hs512

	string hs512Token = encode(["language": "D"], hs_secret, JWTAlgorithm.HS512);
	assert(hs512Token == "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJsYW5ndWFnZSI6IkQifQ.tDRXngYs15t6Q-9AortMxXNfvTgVjaQGD9VTlwL3JD6Xxab8ass2ekCoom8uOiRdpZ772ajLQD42RXMuALct1Q");
	assert(verify(hs512Token, hs_secret));

	version(UsePhobos) {
		//Not supported
	} else {
        // rs256

        string rs256Token = encode(["language": "D"], private256, JWTAlgorithm.RS256);
        assert(rs256Token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYW5ndWFnZSI6IkQifQ.BYpRNUNsho1Yquq7Uolp31K2Ng90h0hRlMV6J6d9WSSIYf7s2MBX2xgDlBuHtB-Yb9dkbkfdxqjYCQdWejiMc_II6dn72ZSBwBCyWdPPRNbTRA2DNlsoKFBS5WMp7iYordfD9KE0LowK61n_Z7AHNAiOop5Ka1xTKH8cqEo8s3ItgoxZt8mzAfhIYNogGown6sYytqg1I72UHsEX9KAuP7sCxCbxZ9cSVg2f4afEuwwo08AdG3hW_LXhT7VD-EweDmvF2JLAyf1_rW66PMgiZZCLQ6kf2hQRsa56xRDmo5qC98wDseBHx9f3PsTsracTKojwQUdezDmbHv90vCt-Iw");
        assert(verify(rs256Token, public256));

        // es256

        string es256Token = encode(["language": "D"], es256_private, JWTAlgorithm.ES256);
        assert(verify(es256Token, es256_public));
	}
}
