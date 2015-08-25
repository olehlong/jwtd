module jwtd.jwt_botan;

import jwtd.jwt;

version (UseBotan) {

	import botan.rng.auto_rng;
	import botan.mac.hmac;
	import botan.hash.hash;
	import botan.hash.sha2_32 : SHA256;
	import botan.hash.sha2_64 : SHA384, SHA512;
	import memutils.unique;

	string sign(string msg, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
		ubyte[] sign;

		void sign_hs(HashFunction hashFun) {
			Unique!HMAC hmac = new HMAC(hashFun);

			hmac.setKey(cast(const(ubyte)*)key.ptr, key.length);
			hmac.update(msg);
			sign = hmac.finished()[].dup;
		}

		void sign_rs(string emsaName) {
			import botan.filters.data_src;
			import x509 = botan.pubkey.x509_key;
			import botan.pubkey.algo.rsa;
			
			Unique!AutoSeededRNG rng = new AutoSeededRNG;
			auto privKey = loadKey(cast(DataSource)DataSourceMemory(key), *rng);
			auto signer = PKSigner(privKey, emsaName);
			sign = signer.signMessage(cast(const(ubyte)*)msg.ptr, msg.length, *rng)[].dup;
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
				sign_rs("EMSA3(SHA-256)");
				break;
			case JWTAlgorithm.RS384:
				sign_rs("EMSA3(SHA-384)");
				break;
			case JWTAlgorithm.RS512:
				sign_rs("EMSA3(SHA-512)");
				break;
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
			default:
				throw new SignException("Wrong algorithm.");
		}

		return cast(string)sign;
	}

	bool verifySignature(string signature, string signing_input, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {

		bool verify_rs(string emsaName) {
			import x509 = botan.pubkey.x509_key;
			import botan.pubkey.algo.rsa;
			import botan.filters.data_src;

			auto pubKey = x509.loadKey(cast(DataSource)DataSourceMemory(key));
			auto verifier = PKVerifier(pubKey, emsaName);
			return verifier.verifyMessage(
				cast(const(ubyte)*)signing_input.ptr, signing_input.length,
				cast(const(ubyte)*)signature.ptr, signature.length);
		}

		switch(algo) {
			case JWTAlgorithm.NONE:
				return true;
			case JWTAlgorithm.HS256:
			case JWTAlgorithm.HS384:
			case JWTAlgorithm.HS512:
				return signature == sign(signing_input, key, algo);
			case JWTAlgorithm.RS256:
				return verify_rs("EMSA3(SHA-256)");
			case JWTAlgorithm.RS384:
				return verify_rs("EMSA3(SHA-384)");
			case JWTAlgorithm.RS512:
				return verify_rs("EMSA3(SHA-512)");
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
			default:
				throw new VerifyException("Wrong algorithm.");
		}
	}
}
