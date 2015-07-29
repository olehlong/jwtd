module jwtd.jwt_botan;

import jwtd.jwt;
import botan.mac.hmac;
import botan.hash.hash;
import botan.hash.sha2_32 : SHA256;
import botan.hash.sha2_64 : SHA384, SHA512;
import memutils.unique;

version (UseBotan) {
	string sign(string msg, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
		ubyte[] sign;

		void sign_hs(HashFunction hashFun) {
			Unique!HMAC hmac = new HMAC(hashFun);
			
			hmac.setKey(cast(const(ubyte)*)key.ptr, key.length);
			hmac.update(msg);
			sign = hmac.finished()[].dup;
		}
			
		switch(algo) {
			case JWTAlgorithm.NONE: {
				break;
			}
			case JWTAlgorithm.HS256: {
				Unique!SHA256 hash = new SHA256();
				sign_hs(*hash);
				break;
			}
			case JWTAlgorithm.HS384: {
				Unique!SHA384 hash = new SHA384();
				sign_hs(*hash);
				break;
			}
			case JWTAlgorithm.HS512: {
				Unique!SHA512 hash = new SHA512();
				sign_hs(*hash);
				break;
			}
			case JWTAlgorithm.RS256:
			case JWTAlgorithm.RS384:
			case JWTAlgorithm.RS512:
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
			default:
				throw new SignException("Wrong algorithm");
		}
		
		return cast(string)sign;
	}

	bool verifySignature(string signature, string signing_input, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
		
		switch(algo) {
			case JWTAlgorithm.NONE: {
				return true;
			}
			case JWTAlgorithm.HS256:
			case JWTAlgorithm.HS384:
			case JWTAlgorithm.HS512: {
				return signature == sign(signing_input, key, algo);
			}
			case JWTAlgorithm.RS256:
			case JWTAlgorithm.RS384:
			case JWTAlgorithm.RS512:
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
			default:
				throw new VerifyException("Wrong algorithm.");
		}
	}
}
