module jwtd.jwt_phobos;

version (UsePhobos) {
	import jwtd.jwt;

	string sign(string msg, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
		import std.digest.sha;
		import std.digest.hmac;

		ubyte[] sign;
		
		void sign_hs(SHA)() {
			import std.string : representation;

			auto hmac = HMAC!SHA(key.representation);
			hmac.put(msg.representation);
			sign = hmac.finish().dup;
		}
		
		switch(algo) {
			case JWTAlgorithm.NONE: {
				break;
			}
			case JWTAlgorithm.HS256: {
				sign_hs!SHA256();
				break;
			}
			case JWTAlgorithm.HS384: {
				sign_hs!SHA384();
				break;
			}
			case JWTAlgorithm.HS512: {
				sign_hs!SHA512();
				break;
			}
			case JWTAlgorithm.RS256:
			case JWTAlgorithm.RS384:
			case JWTAlgorithm.RS512:
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
				throw new SignException("Unsupported algorithm.");
			default:
				throw new SignException("Wrong algorithm.");
		}
		
		return cast(string)sign;
	}
	
	bool verifySignature(string signature, string signing_input, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
		switch(algo) {
			case JWTAlgorithm.NONE:
				return true;
			case JWTAlgorithm.HS256:
			case JWTAlgorithm.HS384:
			case JWTAlgorithm.HS512:
				return signature == sign(signing_input, key, algo);
			case JWTAlgorithm.RS256:
			case JWTAlgorithm.RS384:
			case JWTAlgorithm.RS512:
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
				throw new SignException("Unsupported algorithm.");
			default:
				throw new VerifyException("Wrong algorithm.");
		}
	}
}
