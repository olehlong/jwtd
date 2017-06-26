module jwtd.jwt_openssl;

version(UseOpenSSL) {

	import deimos.openssl.ssl;
	import deimos.openssl.pem;
	import deimos.openssl.rsa;
	import deimos.openssl.hmac;
	import deimos.openssl.err;

	import jwtd.jwt : JWTAlgorithm, SignException, VerifyException;

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

	EC_KEY* getESPrivateKey(uint curve_type, string key) {
		EC_GROUP* curve;
		EVP_PKEY* pktmp;
		BIO* bpo;

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

		EC_GROUP_free(curve);

		return eckey;
	}

	EC_KEY* getESPublicKey(uint curve_type, string key) {
		EC_GROUP* curve;

		if(null == (curve = EC_GROUP_new_by_curve_name(curve_type)))
			throw new Exception("Unsupported curve.");

		EC_KEY* eckey = EC_KEY_new();

		BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
		if(bpo is null) {
			EC_GROUP_free(curve);
			throw new Exception("Can't load the key.");
		}

		eckey = PEM_read_bio_EC_PUBKEY(bpo, null, null, null);

		if(1 != EC_KEY_set_group(eckey, curve)) {
			BIO_free(bpo);
			EC_GROUP_free(curve);

			throw new Exception("Can't associate group with the key.");
		}

		BIO_free(bpo);
		EC_GROUP_free(curve);

		if(0 == EC_KEY_check_key(eckey))
			throw new Exception("Public key is not valid.");

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
			EC_KEY* eckey = getESPrivateKey(curve_type, key);
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
				throw new SignException("Wrong algorithm.");
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
			EC_KEY* eckey = getESPublicKey(curve_type, key);
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
				return key.length == 0;
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
