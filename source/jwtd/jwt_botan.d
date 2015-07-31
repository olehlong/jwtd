module jwtd.jwt_botan;

import jwtd.jwt;

version (UseBotan) {

	import botan.rng.auto_rng;
	import botan.mac.hmac;
	import botan.hash.hash;
	import botan.hash.sha2_32 : SHA256;
	import botan.hash.sha2_64 : SHA384, SHA512;
	import botan.pubkey.algo.rsa;
	import botan.filters.data_src;
	import x509 = botan.pubkey.x509_key;
	import memutils.unique;

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
				Unique!AutoSeededRNG rng = new AutoSeededRNG;
				auto privKey = loadKey(cast(DataSource)DataSourceMemory(key), *rng);
				auto signer = PKSigner(privKey, "EMSA3(SHA-256)");
				sign = signer.signMessage(cast(const(ubyte)*)msg.ptr, msg.length, *rng)[];

				auto verifier = PKVerifier(privKey, "EMSA3(SHA-256)");
				assert(verifier.verifyMessage(
					cast(const(ubyte)*)msg.ptr, msg.length,
					cast(const(ubyte)*)sign.ptr, sign.length));
				break;
			case JWTAlgorithm.RS384:
			case JWTAlgorithm.RS512:
			case JWTAlgorithm.ES256:
			case JWTAlgorithm.ES384:
			case JWTAlgorithm.ES512:
			default:
				throw new SignException("Wrong algorithm.");
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
				auto pubKey = x509.loadKey(cast(DataSource)DataSourceMemory(key));
				auto verifier = PKVerifier(pubKey, "EMSA3(SHA-256)");
				return verifier.verifyMessage(
					cast(const(ubyte)*)signing_input.ptr, signing_input.length,
					cast(const(ubyte)*)signature.ptr, signature.length);
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
