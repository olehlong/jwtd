module jwtd.jwt;

import std.json;
import std.stdio;
import std.base64;
import std.algorithm;
import std.array : split;

version (UseBotan) {
	import jwtd.jwt_botan;
}
else {
	import deimos.openssl.ssl;
	import deimos.openssl.pem;
	import deimos.openssl.rsa;
	import deimos.openssl.hmac;
	import deimos.openssl.err;
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
	if(header_fields.type == JSON_TYPE.NULL)
		header_fields = (JSONValue[string]).init;
	header_fields.object["alg"] = cast(string)algo;
	header_fields.object["typ"] = "JWT";
	
	string encodedHeader = urlsafeB64Encode(header_fields.toString());
	string encodedPayload = urlsafeB64Encode(payload.toString());
	
	string signingInput = encodedHeader ~ "." ~ encodedPayload;
	string signature = urlsafeB64Encode(sign(signingInput, key, algo));
	
	return signingInput ~ "." ~ signature;
}

JSONValue decode(string token, string key) {
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
	
	string typ = header["typ"].str();
	if(typ && typ != "JWT")
		throw new VerifyException("Type is incorrect.");
	
	if(!verifySignature(urlsafeB64Decode(tokenParts[2]), tokenParts[0]~"."~tokenParts[1], key, alg))
		throw new VerifyException("Signature is incorrect.");
	
	JSONValue payload;
	
	try {
		payload = parseJSON(urlsafeB64Decode(tokenParts[1]));
	} catch(JSONException e) {
		throw new VerifyException("Payload JSON is incorrect.");
	}
	
	return payload;
}

version (UseBotan) { }
else {
EC_KEY* getESKeypair(uint curve_type, string key) {
	EC_GROUP* curve;
	EVP_PKEY* pktmp;
	BIO* bpo; 
	EC_POINT* pub;
	
	if(null == (curve = EC_GROUP_new_by_curve_name(curve_type)))
		throw new Exception("Unsupported curve.");

	bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
	if(bpo is null) {
		EC_GROUP_free(curve);
		throw new Exception("Can't load the key.");
	}

	pktmp = PEM_read_bio_PrivateKey(bpo, null, null, null);
	if(pktmp is null) {
		EC_GROUP_free(curve);
		BIO_free(bpo);

		throw new Exception("Can't load the evp_pkey.");
	}

	BIO_free(bpo);

	EC_KEY * eckey;
 	eckey = EVP_PKEY_get1_EC_KEY(pktmp);
	EVP_PKEY_free(pktmp);
	
	if(eckey is null) {
		EC_GROUP_free(curve);
		
		throw new Exception("Can't convert evp_pkey to EC_KEY.");
	}
	if(1 != EC_KEY_set_group(eckey, curve)) {
		EC_GROUP_free(curve);
		
		throw new Exception("Can't associate group with the key.");
	}

	const BIGNUM *prv = EC_KEY_get0_private_key(eckey);
	if(null == prv) {
		EC_GROUP_free(curve);
		
		throw new Exception("Can't get private ke.y");
	}

	pub = EC_POINT_new(curve);

	if (1 != EC_POINT_mul(curve, pub, prv, null, null, null)) {
		EC_GROUP_free(curve);
		EC_POINT_free(pub);

		throw new Exception("Can't calculate public key.");
	}
		
	if(1 != EC_KEY_set_public_key(eckey, pub)) {
		EC_GROUP_free(curve);
		EC_POINT_free(pub);
		
		throw new Exception("Can't set public key.");
	}
	
	EC_GROUP_free(curve);
	EC_POINT_free(pub);
	
	return eckey;
}

string sign(string msg, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
	ubyte[] sign;

	void sign_hs(const(EVP_MD)* evp, uint signLen) {
		sign = new ubyte[signLen];

		HMAC_CTX ctx;
		HMAC_CTX_init(&ctx);
		HMAC_Init_ex(&ctx, key.ptr, cast(int)key.length, evp, null);
		HMAC_Update(&ctx, cast(const(ubyte)*)msg.ptr, cast(ulong)msg.length);
		HMAC_Final(&ctx, cast(ubyte*)sign.ptr, &signLen);
		HMAC_CTX_cleanup(&ctx);
	}

	void sign_rs(ubyte* hash, int type, uint len, uint signLen) {
		sign = new ubyte[len];
		
		RSA* rsa_private = RSA_new();
		BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
		if(bpo is null)
			throw new Exception("Can't load the key.");
		PEM_read_bio_RSAPrivateKey(bpo, &rsa_private, null, null);
		BIO_free(bpo);
		if(rsa_private is null)
			throw new Exception("Can't create RSA key.");
		RSA_sign(type, hash, signLen, sign.ptr, &signLen, rsa_private);
		RSA_free(rsa_private);
	}
	
	void sign_es(uint curve_type, ubyte* hash, int hashLen) {
		EC_KEY* eckey = getESKeypair(curve_type, key);
		ECDSA_SIG* sig = ECDSA_do_sign(hash, hashLen, eckey);
		if(sig is null) {
			EC_KEY_free(eckey);
			
			throw new Exception("Digest sign failed.");
		}
		
		sign = new ubyte[ECDSA_size(eckey)];
		ubyte* c = sign.ptr;
		if(!i2d_ECDSA_SIG(sig, &c)) {
			ECDSA_SIG_free(sig);
			EC_KEY_free(eckey);
			throw new Exception("Convert sign to DER format failed.");
		}
	}

	switch(algo) {
		case JWTAlgorithm.NONE: {
			break;
		}
		case JWTAlgorithm.HS256: {	
			sign_hs(EVP_sha256(), SHA256_DIGEST_LENGTH);
			break;
		}
		case JWTAlgorithm.HS384: {
			sign_hs(EVP_sha384(), SHA384_DIGEST_LENGTH);
			break;
		}
		case JWTAlgorithm.HS512: {
			sign_hs(EVP_sha512(), SHA512_DIGEST_LENGTH);
			break;
		}
		case JWTAlgorithm.RS256: {
			ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
			SHA256(cast(const(ubyte)*)msg.ptr, msg.length, hash.ptr);
			sign_rs(hash.ptr, NID_sha256, 256, SHA256_DIGEST_LENGTH);
			break;
		}
		case JWTAlgorithm.RS384: {
			ubyte[] hash = new ubyte[SHA384_DIGEST_LENGTH];
			SHA384(cast(const(ubyte)*)msg.ptr, msg.length, hash.ptr);
			sign_rs(hash.ptr, NID_sha384, 384, SHA384_DIGEST_LENGTH);
			break;
		}
		case JWTAlgorithm.RS512: {
			ubyte[] hash = new ubyte[SHA512_DIGEST_LENGTH];
			SHA512(cast(const(ubyte)*)msg.ptr, msg.length, hash.ptr);
			sign_rs(hash.ptr, NID_sha512, 512, SHA512_DIGEST_LENGTH);
			break;
		}
		case JWTAlgorithm.ES256: {
			ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
			SHA256(cast(const(ubyte)*)msg.ptr, msg.length, hash.ptr);
			sign_es(NID_secp256k1, hash.ptr, SHA256_DIGEST_LENGTH);
			break;
		} 
		case JWTAlgorithm.ES384: {
			ubyte[] hash = new ubyte[SHA384_DIGEST_LENGTH];
			SHA384(cast(const(ubyte)*)msg.ptr, msg.length, hash.ptr);
			sign_es(NID_secp384r1, hash.ptr, SHA384_DIGEST_LENGTH);
			break;
		} 
		case JWTAlgorithm.ES512: {
			ubyte[] hash = new ubyte[SHA512_DIGEST_LENGTH];
			SHA512(cast(const(ubyte)*)msg.ptr, msg.length, hash.ptr);
			sign_es(NID_secp521r1, hash.ptr, SHA512_DIGEST_LENGTH);
			break;
		} 
			
		default:
			throw new SignException("Wrong algorithm");
	}
	
	return cast(string)sign;
}

bool verifySignature(string signature, string signing_input, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
	
	bool verify_rs(ubyte* hash, int type, uint len, uint signLen) {
		RSA* rsa_public = RSA_new();
		BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
		if(bpo is null)
			throw new Exception("Can't load key to the BIO.");
		PEM_read_bio_RSA_PUBKEY(bpo, &rsa_public, null, null);
		BIO_free(bpo);
		if(rsa_public is null)
			throw new Exception("Can't create RSA key.");
		ubyte[] sign = cast(ubyte[])signature;
		int ret = RSA_verify(type, hash, signLen, sign.ptr, len, rsa_public);
		RSA_free(rsa_public);
		return ret == 1;
	}
	
	bool verify_es(uint curve_type, ubyte* hash, int hashLen ) {
		EC_KEY* eckey = getESKeypair(curve_type, key);
		ubyte* c = cast(ubyte*)signature.ptr;
		ECDSA_SIG* sig = null;
		
		sig = d2i_ECDSA_SIG(&sig, cast(const (ubyte)**)&c, cast(int) key.length);
		int ret =  ECDSA_do_verify(hash, hashLen, sig, eckey);
		
		ECDSA_SIG_free(sig);
		EC_KEY_free(eckey);
		
		return ret == 1;
	}
	
	switch(algo) {
		case JWTAlgorithm.NONE: {
			return true;
		}
		case JWTAlgorithm.HS256:
		case JWTAlgorithm.HS384:
		case JWTAlgorithm.HS512: {
			return signature == sign(signing_input, key, algo);
		}
		case JWTAlgorithm.RS256: {
			ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
			SHA256(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
			return verify_rs(hash.ptr, NID_sha256, 256, SHA256_DIGEST_LENGTH);
		}
		case JWTAlgorithm.RS384: {
			ubyte[] hash = new ubyte[SHA384_DIGEST_LENGTH];
			SHA384(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
			return verify_rs(hash.ptr, NID_sha384, 384, SHA384_DIGEST_LENGTH);
		}
		case JWTAlgorithm.RS512: {
			ubyte[] hash = new ubyte[SHA512_DIGEST_LENGTH];
			SHA512(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
			return verify_rs(hash.ptr, NID_sha512, 512, SHA512_DIGEST_LENGTH);
		}
			
		case JWTAlgorithm.ES256:{
			ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
			SHA256(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
			return verify_es(NID_secp256k1, hash.ptr, SHA256_DIGEST_LENGTH );
		}
		case JWTAlgorithm.ES384:{
			ubyte[] hash = new ubyte[SHA384_DIGEST_LENGTH];
			SHA384(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
			return verify_es(NID_secp384r1, hash.ptr, SHA384_DIGEST_LENGTH );
		}
		case JWTAlgorithm.ES512: {
			ubyte[] hash = new ubyte[SHA512_DIGEST_LENGTH];
			SHA512(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
			return verify_es(NID_secp521r1, hash.ptr, SHA512_DIGEST_LENGTH );
		}

		default:
			throw new VerifyException("Wrong algorithm.");
	}
}
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
	
	string typ = header["typ"].str();
	if(typ && typ != "JWT")
		throw new VerifyException("Type is incorrect.");
	
	return verifySignature(urlsafeB64Decode(tokenParts[2]), tokenParts[0]~"."~tokenParts[1], key, alg);
}

/**
 * Encode a string with URL-safe Base64.
 */
string urlsafeB64Encode(string inp) {
	import std.string : removechars;
	
	char[] enc = Base64URL.encode(cast(ubyte[])inp);
	return removechars(cast(string)(enc), "=");
}

/**
 * Decode a string with URL-safe Base64.
 */
string urlsafeB64Decode(string inp) {
	import std.array : replicate, join;
	
	int remainder = inp.length % 4;
	if(remainder > 0) {
		int padlen = 4 - remainder;
		inp ~= replicate("=", padlen);
	}
	return cast(string)(Base64URL.decode(cast(ubyte[])inp));
}

unittest {

	string private256 = q"EOS
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq+e/dME9Mrklp8hvhzqoAq+CWCyOHQrsoMhyuqieTr3QfURt
UY+d9VV0NhfgSRrbzsYGodOV+suo5jr/zi/zTDfEvDFjIVz2HffzTzriQ/q4nF2p
ZqfaS+ctqq6wIa5E05abW4mK6vz1Xnuqi1wu8KfUZjEA5U8Za5MpM4E6P624zMz+
N8C9k6LyNgE3Pr9eU+t7obZNZnQCLBF4g5YxYQ+mpVvPrR5WZhfRCRET3whPC0kR
xy7f1dBxpxq9z6udfUP5S/UyUqlieMeC6Y8+9eag7Df//GhHb8MlUUgAlTXnHhOL
f1lUEqlWWcHxJc9stbgMsPCOlvkurQCV36HOSQIDAQABAoIBAFtk48JUNpAwJVf1
1W3E/qwm2Zq9XXUNaM72oyCgI0Jj4mOnLKOvQmC75QQZX5IeaHyfhcklr9hdzNdS
yMu7bJO6FqujajvDq8o1GDOob8GKm/nuRfEhDotKRlo3c8cEWu1PZhudnbDfeiiY
gQyEnyQtZlxKc1p22mH6JG6QpwJRH5iaxaCcAY+zxXDf1NJcqLtlCQfPycLT8fPW
OFVUrtUnUG8DEm8V8r1oHh6UsCQsrQbB20qWJdiQxr9W2riw6eO/EnK9vsXXqRGz
rXyuaE2zZezgURthgVYiPpe+OrDyeUWdpn1Uoh0PrFzPtLVEjYpMmT5TpBkbhKBS
/4re050CgYEA4JmOwOXg99kedusy5cghsEXI3fN/fUaAj2nfP3rjJaLEiMOSm/mN
8CDGdoOKXmhk7w1up3v2AMAEyKbIdrMAVc/m9GiKNPuiONlHZW/xQGBil9MY84Nh
WUswg0fg70u4OnpfyYnbrnDPt+BpKIO0n5W6TzDs4iFogTlaky5B77cCgYEAw/A/
jZBIxyYUJgext7aoh/WY3d/gHmAyimk0gawQszIQF4248HGPm3ZTL8FoXAMCNFEA
t03sNubIhybS6bHz+gi2P/vNUGGrw3bdXW4geWoaZGwfDmKg0B/q7yOH3MhJ1oSh
mhImyN1QGPp3fctdaax78JnGTm5aXIBAc1d+Mf8CgYBAbq0OV6RHVgkwUl8CnnxT
pmFukvlDBiPBgLzj6Cwb0usQ1RJNHrWCatSkkS3z0X0LO05ATAaRxoRYz8f4jXeO
Jpt6CDeF5Z5vMp4R0qBiOIRwS8X/rfQSesiLEObNn2pVlF/AYIUeMQzWElH4pnf9
xCVzrHR4lt71G3AJgx61VwKBgQCraSDgAkp41kooHvENK+Fx15xc9f6F9Fgil/jU
PCf77B8By/zvdBlSwofxrjxSylsCU57RvXyZZvokqgU3ZnNu2HI/tVQfLuLpw7HS
i4YjUXw3QBNHLWdLy7Bmdmnj7uARp8QMGjcN3/azc2JXjTJyQO/IQ26lrIqmg5he
jzsaFwKBgBLI/WJkvP5IKCSE4zSCOtOMKMMXDEv3lH30O2z4syw2ET0ENAioQDwv
r1c/sFsyUoBwnLmJhwYxuveNBLYYNfgLFsJJvPd1Req+ni47e28qKn2iRG7GZvct
pkIt+dzxyAoauwspxEEiPpGjz91dvBSG9qLcqNQ+BF4X4byB9itQ
-----END RSA PRIVATE KEY-----
EOS";

	string public256 = q"EOS
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+e/dME9Mrklp8hvhzqo
Aq+CWCyOHQrsoMhyuqieTr3QfURtUY+d9VV0NhfgSRrbzsYGodOV+suo5jr/zi/z
TDfEvDFjIVz2HffzTzriQ/q4nF2pZqfaS+ctqq6wIa5E05abW4mK6vz1Xnuqi1wu
8KfUZjEA5U8Za5MpM4E6P624zMz+N8C9k6LyNgE3Pr9eU+t7obZNZnQCLBF4g5Yx
YQ+mpVvPrR5WZhfRCRET3whPC0kRxy7f1dBxpxq9z6udfUP5S/UyUqlieMeC6Y8+
9eag7Df//GhHb8MlUUgAlTXnHhOLf1lUEqlWWcHxJc9stbgMsPCOlvkurQCV36HO
SQIDAQAB
-----END PUBLIC KEY-----
EOS";

string es256_key = q"EOS
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIB8cQPtLEF5hOJsom5oVU5dMpgDUR2QYuJTXdtvxezQloAcGBSuBBAAK
oUQDQgAEMuSnsWbiIPyfFAIAvlbliPOUnQlibb67yE6JUqXVaevb8ZorK2HfxfFg
9pGVhg3SGuBCbHcJ84WKOX3GSMEwcA==
-----END EC PRIVATE KEY-----
EOS"; 
	string hs_secret = "secret";
	
	// none
	
	string noneToken = encode(["language": "D"], "", JWTAlgorithm.NONE);
	assert(noneToken == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsYW5ndWFnZSI6IkQifQ.");
	assert(verify(noneToken, ""));
	
	// hs256
	
	string hs256Token = encode(["language": "D"], hs_secret, JWTAlgorithm.HS256);
	assert(hs256Token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYW5ndWFnZSI6IkQifQ.utQLevAUK97y-e6B3-EnSofvTNAfSXNuSbu4moAh-hY");
	assert(verify(hs256Token, hs_secret));
	
	// hs512
	
	string hs512Token = encode(["language": "D"], hs_secret, JWTAlgorithm.HS512);
	assert(hs512Token == "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJsYW5ndWFnZSI6IkQifQ.tDRXngYs15t6Q-9AortMxXNfvTgVjaQGD9VTlwL3JD6Xxab8ass2ekCoom8uOiRdpZ772ajLQD42RXMuALct1Q");
	assert(verify(hs512Token, hs_secret));

	version (UseBotan) { /*Not implemented yet */ }
	else {
	// rs256
	
	string rs256Token = encode(["language": "D"], private256, JWTAlgorithm.RS256);
	assert(rs256Token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYW5ndWFnZSI6IkQifQ.BYpRNUNsho1Yquq7Uolp31K2Ng90h0hRlMV6J6d9WSSIYf7s2MBX2xgDlBuHtB-Yb9dkbkfdxqjYCQdWejiMc_II6dn72ZSBwBCyWdPPRNbTRA2DNlsoKFBS5WMp7iYordfD9KE0LowK61n_Z7AHNAiOop5Ka1xTKH8cqEo8s3ItgoxZt8mzAfhIYNogGown6sYytqg1I72UHsEX9KAuP7sCxCbxZ9cSVg2f4afEuwwo08AdG3hW_LXhT7VD-EweDmvF2JLAyf1_rW66PMgiZZCLQ6kf2hQRsa56xRDmo5qC98wDseBHx9f3PsTsracTKojwQUdezDmbHv90vCt-Iw");
	assert(verify(rs256Token, public256));
	
	// es256
	
	string es256Token = encode(["language": "D"], es256_key, JWTAlgorithm.ES256);
	assert(verify(es256Token, es256_key));
	}
}
