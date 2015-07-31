module jwtd.jwt_botan;

import jwtd.jwt;

version (UseBotan) {

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

//		void sign_rs(ubyte* hash, int type, uint len, uint signLen) {
//			sign = new ubyte[len];
//
//			RSA* rsa_private = RSA_new();
//			BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
//			if(bpo is null)
//				throw new Exception("Can't load the key.");
//			PEM_read_bio_RSAPrivateKey(bpo, &rsa_private, null, null);
//			BIO_free(bpo);
//			if(rsa_private is null)
//				throw new Exception("Can't create RSA key.");
//			RSA_sign(type, hash, signLen, sign.ptr, &signLen, rsa_private);
//			RSA_free(rsa_private);
//		}

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
				import botan.pubkey.algo.rsa;
				import botan.rng.auto_rng;
				import botan.filters.data_src;
                
                Unique!SHA256 hash = new SHA256();
                hash.update(msg);

				Unique!AutoSeededRNG rng = new AutoSeededRNG;
				auto privKey = loadKey(cast(DataSource)DataSourceMemory(key), *rng);
                auto signer = PKSigner(privKey, "EMSA4(SHA-256)");
                auto res = signer.signMessage(cast(const(ubyte)*)msg.ptr, msg.length, *rng);
                //auto res = signer.signMessage(hash.finished(), *rng);
                sign = res[];
				//sign_rs(hash.ptr, NID_sha256, 256, SHA256_DIGEST_LENGTH);
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
