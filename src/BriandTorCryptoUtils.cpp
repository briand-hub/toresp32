/* 
    Briand TorEsp32 https://github.com/briand-hub/toresp32
    Copyright (C) 2021 Author: briand (https://github.com/briand-hub)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "BriandTorCryptoUtils.hxx"
#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandTorRelay.hxx"

using namespace std;

namespace Briand {

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::GetDigest_SHA256(const unique_ptr<vector<unsigned char>>& input) {	
		// Using mbedtls

		auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

		auto hashedMessageRaw = BriandUtils::GetOneOldBuffer(mdInfo->size);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] SHA256 Raw message to encode: ");
			BriandUtils::PrintByteBuffer(*input.get());
		} 
		
		// Using mbedtls_md() not working as expected!!

		mbedtls_md_context_t mdCtx;

		mbedtls_md_init(&mdCtx);
		mbedtls_md_setup(&mdCtx, mdInfo, 0);
		mbedtls_md_starts(&mdCtx);
		mbedtls_md_update(&mdCtx, input->data(), input->size());
		mbedtls_md_finish(&mdCtx, hashedMessageRaw.get());
		
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] SHA256 Raw output: ");
			BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size, mdInfo->size);
		} 

		auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

		// Free (MUST!)
		mbedtls_md_free(&mdCtx);

		return std::move(digest);
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::GetDigest_SHA1(const unique_ptr<vector<unsigned char>>& input) {	
		// Using mbedtls

		auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		auto hashedMessageRaw = BriandUtils::GetOneOldBuffer(mdInfo->size);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] SHA1 Raw message to encode: ");
			BriandUtils::PrintByteBuffer(*input.get());
		} 
		
		// Using mbedtls_md() not working as expected!!

		mbedtls_md_context_t mdCtx;

		mbedtls_md_init(&mdCtx);
		mbedtls_md_setup(&mdCtx, mdInfo, 0);
		mbedtls_md_starts(&mdCtx);
		mbedtls_md_update(&mdCtx, input->data(), input->size());
		mbedtls_md_finish(&mdCtx, hashedMessageRaw.get());

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] SHA1 Raw output: ");
			BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size, mdInfo->size);
		} 

		auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

		// Free (MUST!)
		mbedtls_md_free(&mdCtx);

		return std::move(digest);
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::GetRelayCellDigest(unique_ptr<mbedtls_md_context_t>& relayCurrentDigest, const unique_ptr<vector<unsigned char>>& relayCellPayload) {
		// Using mbedtls

		auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
		auto hashedMessageRaw = BriandUtils::GetOneOldBuffer(mdInfo->size);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] RELAY CELL DIGEST Raw message to encode: ");
			BriandUtils::PrintByteBuffer(*relayCellPayload.get());
		} 
				
		// Update with input bytes
		mbedtls_md_update(relayCurrentDigest.get(), relayCellPayload->data(), relayCellPayload->size());

		// Make a copy and finalize
		mbedtls_md_context_t mdCopy;
		mbedtls_md_init(&mdCopy);
		mbedtls_md_setup(&mdCopy, mdInfo, 0);
		//mbedtls_md_starts(&mdCopy);
		mbedtls_md_clone(&mdCopy, relayCurrentDigest.get());
		mbedtls_md_finish(&mdCopy, hashedMessageRaw.get());

		// Free (MUST!)
		mbedtls_md_free(&mdCopy);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] RELAY CELL DIGEST Raw output: ");
			BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size, mdInfo->size);
		} 

		auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

		return std::move(digest);
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::GetDigest_HMAC_SHA256(const unique_ptr<vector<unsigned char>>& input, const unique_ptr<vector<unsigned char>>& key) {	
		// Using mbedtls

		auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

		auto hashedMessageRaw = BriandUtils::GetOneOldBuffer(mdInfo->size);

		ESP_LOGD(LOGTAG, "[DEBUG] HMAC-SHA256 Raw message to encode: ");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) BriandUtils::PrintByteBuffer(*input.get());
		
		// Using mbedtls_md() not working as expected!!

		auto mdCtx = make_unique<mbedtls_md_context_t>();

		mbedtls_md_setup(mdCtx.get(), mdInfo, 1); // last 1: specify hmac
		mbedtls_md_hmac_starts(mdCtx.get(), key->data(), key->size());
		mbedtls_md_hmac_update(mdCtx.get(), input->data(), input->size());
		mbedtls_md_hmac_finish(mdCtx.get(), hashedMessageRaw.get());

		// HINT : using this:
		// mbedtls_md_context_t mdCtx;
		// mbedtls_md_setup(&mdCtx, mdInfo, 0);
		// mbedtls_md_starts(&mdCtx);
		// mbedtls_md_update(&mdCtx, inputRaw.get(), input->size());
		// mbedtls_md_finish(&mdCtx, hashedMessageRaw.get());
		// mbedtls_md_free(&mdCtx);

		// will led to:
		// free(): invalid pointer
		// made by calling mbedtls_md_free(&mdCtx);
		// however not calling will leak heap!
		// solution found: use unique_ptr , always working! Thanks C++
		
		ESP_LOGD(LOGTAG, "[DEBUG] HMAC-SHA256 Raw output: ");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size, mdInfo->size);

		auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

		// Free (MUST!)
		mbedtls_md_free(mdCtx.get());

		return std::move(digest);
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::Get_HKDF(const unique_ptr<vector<unsigned char>>& mExpand, const unique_ptr<vector<unsigned char>>& keySeed, const unsigned int bytesToProduce) {
		/*
			K = K_1 | K_2 | K_3 | ...

			Where H(x,t) is HMAC_SHA256 with value x and key t
			and K_1     = H(m_expand | INT8(1) , KEY_SEED )
			and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
			and m_expand is an arbitrarily chosen value,
			and INT8(i) is a octet with the value "i".

			In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
			salt == t_key, and IKM == secret_input.
		*/

		auto hkdfOutput = make_unique<vector<unsigned char>>();
		unsigned char INT8 = 1;
		auto lastHmacOutput = make_unique<vector<unsigned char>>();

		while (hkdfOutput->size() < bytesToProduce) {
			auto hmacInput = make_unique<vector<unsigned char>>();
			hmacInput->insert(hmacInput->end(), lastHmacOutput->begin(), lastHmacOutput->end());
			hmacInput->insert(hmacInput->end(), mExpand->begin(), mExpand->end());
			hmacInput->push_back(INT8);
			lastHmacOutput = BriandTorCryptoUtils::GetDigest_HMAC_SHA256(hmacInput, keySeed);
			hkdfOutput->insert(hkdfOutput->end(), lastHmacOutput->begin(), lastHmacOutput->end());
			INT8++;
		}

		hkdfOutput->resize(bytesToProduce);

		return std::move(hkdfOutput);
	}

	bool BriandTorCryptoUtils::CheckSignature_RSASHA256(const unique_ptr<vector<unsigned char>>& message, const unique_ptr<vector<unsigned char>>& x509DerCertificate, const unique_ptr<vector<unsigned char>>& signature) {
		// Using mbedtls

		// First, calculate hash SHA256 of the message
		auto messageHash = GetDigest_SHA256(message);
		constexpr unsigned short DIGEST_SIZE = 32;

		// Structures needed
		mbedtls_x509_crt rsaIde;
		mbedtls_x509_crt_init(&rsaIde);

		// Extract the PK from the certificate

		if ( mbedtls_x509_crt_parse(&rsaIde, x509DerCertificate->data(), x509DerCertificate->size()) != 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] CheckSignature RSA/SHA256: failed to parse certificate.\n");
			
			// Free
			mbedtls_x509_crt_free(&rsaIde);
			return false;
		}

		// Thanks a lot @gilles-peskine-arm for resolving the problem! ( https://github.com/ARMmbed/mbedtls/issues/4400 )
		// Using MBEDTLS_MD_NONE because this is raw data, and this function expects a signature with added information data
		// about the MD used.
		int verifyResult = mbedtls_pk_verify(&rsaIde.pk, MBEDTLS_MD_NONE, messageHash->data(), DIGEST_SIZE, signature->data(), signature->size());

		if (verifyResult != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(verifyResult, reinterpret_cast<char*>(errBuf.get()), 128);

			ESP_LOGD(LOGTAG, "[DEBUG] CheckSignature RSA/SHA256 signature INVALID: %s\n", reinterpret_cast<char*>(errBuf.get()));
			
			// Free
			mbedtls_x509_crt_free(&rsaIde);
			return false;
		}

		// Free (MUST!)
		mbedtls_x509_crt_free(&rsaIde);

		ESP_LOGD(LOGTAG, "[DEBUG] CheckSignature RSA/SHA256 signature valid.\n");

		return true;
	}	

	bool BriandTorCryptoUtils::X509Validate(const unique_ptr<vector<unsigned char>>& x509PeerCertificate, const unique_ptr<vector<unsigned char>>& x509CACertificate) {
		// Using mbedtls

		// Data structures needed
		mbedtls_x509_crt chain;
		mbedtls_x509_crt root_ca;
		mbedtls_x509_crt_profile profile;

		// Initialize data structures
		mbedtls_x509_crt_init(&chain);
		mbedtls_x509_crt_init(&root_ca);
		
		// Copy the default profile and set it to allow a 1024 RSA key
		// Otherwise will throw "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)."
		memcpy(&profile, &mbedtls_x509_crt_profile_default, sizeof(mbedtls_x509_crt_profile_default) );

		// Allow 1024 RSA keys
		profile.rsa_min_bitlen = 1024;

		// Start to parse the CA and add it to chain
		// CA MUST BE THE FIRST IN THE CHAIN!!!
		// MUST be zero-init

		// Parse CA and add to chain
		if (mbedtls_x509_crt_parse(&chain, x509CACertificate->data(), x509CACertificate->size()) != 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] X509Validate: failed to parse CA certificate.\n");

			// free
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return false;
		}	

		// Parse CA again but add to ROOTCA chain to verify against
		mbedtls_x509_crt_parse(&root_ca, x509CACertificate->data(), x509CACertificate->size());

		// Parse Peer and add to chain
		if ( mbedtls_x509_crt_parse(&chain, x509PeerCertificate->data(), x509PeerCertificate->size()) != 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] X509Validate: failed to parse peer certificate.\n");

			// free
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return false;
		}

		// Validate
		// to see validation results the verify callback could be added.
		unsigned int verification_flags;
		
		if (mbedtls_x509_crt_verify_with_profile(&chain, &root_ca, NULL,  &profile, NULL, &verification_flags, NULL, NULL) != 0) {
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				auto tempBuffer = BriandUtils::GetOneOldBuffer(256 + 1);
				mbedtls_x509_crt_verify_info( reinterpret_cast<char*>(tempBuffer.get()), 256, "", verification_flags);
				printf("[DEBUG] X509Validate failed because %s\n", reinterpret_cast<const char*>(tempBuffer.get()));
			} 

			// free 
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] X509Validate: success.\n");

		// free data structs
		mbedtls_x509_crt_free(&chain);
		mbedtls_x509_crt_free(&root_ca);

		return true;
	}

	bool BriandTorCryptoUtils::CheckSignature_Ed25519(const unique_ptr<vector<unsigned char>>& message, const unique_ptr<vector<unsigned char>>& ed25519PK, const unique_ptr<vector<unsigned char>>& signature) {
		// using libsodium

		// initializes the library and should be called before any other function provided by Sodium. 
		// It is safe to call this function more than once and from different threads -- subsequent calls won't have any effects.
		// After this function returns, all of the other functions provided by Sodium will be thread-safe.
		// sodium_init() doesn't perform any memory allocations
		// Multiple calls to sodium_init() do not cause additional descriptors to be opened.
		// sodium_init() returns 0 on success, -1 on failure, and 1 if the library had already been initialized
		if (sodium_init() < 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] CheckSignature Ed25519 Error on sodium_init()\n");
			return false;
		}

		// Verify

		if (crypto_sign_verify_detached(signature->data(), message->data(), message->size(), ed25519PK->data()) != 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] CheckSignature Ed25519 signature is not valid.\n");
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] CheckSignature Ed25519 signature valid.\n");

		return true;
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::Base64Decode(const string& input) {
		// using mbedtls
		
		auto output = make_unique<vector<unsigned char>>();
		size_t outSize;
		
		// test the output size
		mbedtls_base64_decode(NULL, 0, &outSize, reinterpret_cast<const unsigned char*>(input.c_str()), input.length());
		
		if (outSize > 0) {
			// prepare buffer
			auto buffer = BriandUtils::GetOneOldBuffer(outSize);
			unsigned int bLen = outSize;
			mbedtls_base64_decode(buffer.get(), bLen, &outSize, reinterpret_cast<const unsigned char*>(input.c_str()), input.length());
			for (unsigned int i=0; i<bLen; i++) {
				output->push_back(buffer[i]);
			}
		}
		
		return output;
	}

	bool BriandTorCryptoUtils::ECDH_Curve25519_GenKeys(BriandTorRelay& relay) {
		// using mbedtls

		// If output had a previous initialization, clear it!
		if (relay.CURVE25519_PRIVATE_KEY != nullptr) relay.CURVE25519_PRIVATE_KEY.reset();
		if (relay.CURVE25519_PUBLIC_KEY != nullptr) relay.CURVE25519_PUBLIC_KEY.reset();

		// Structures needed
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;

		string pers = "BriandTorCryptoUtils::ECDH_Curve25519_GenKeys";
		int ret;

		// Initialize random number generation
		mbedtls_ctr_drbg_init( &ctr_drbg );
		mbedtls_entropy_init( &entropy );
		ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(pers.c_str()), pers.length() );
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_GenKeys failed initialize RNG: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ctr_drbg_free( &ctr_drbg );
			mbedtls_entropy_free( &entropy );
			return false;
		}

		// Prepare Curve25519 parameters
		mbedtls_ecp_group ecpGroup;
		mbedtls_ecp_group_init(&ecpGroup);
		mbedtls_ecp_group_load(&ecpGroup, MBEDTLS_ECP_DP_CURVE25519);

		// This:
		// char bb[32] = {0x00};
		// unsigned long int bbs;
		// mbedtls_mpi_write_string(&ecpGroup.G.X, 16, bb, 32, &bbs);
		// printf("Gx = %s\n", bb);
		// Gives output => Gx = 0x09 (big endian!)
		// So default params ok!
		// But that means also that mbedtls implementation works with REVERSE order!!

		// Use G = 9
		// auto Gx = make_unique<unsigned char[]>(32); 
		// Gx[31] = 0x09;// 9 followed by all 0 (WARNING! LITTLE ENDIAN FORMAT!)
		// mbedtls_ecp_point G;
		// mbedtls_ecp_point_init(&G);
		// mbedtls_mpi_read_binary(&G.X, Gx.get(), 32);
		// mbedtls_mpi_lset(&G.Z, 1); // not infinity

		// Key generation
		auto keypair = make_unique<mbedtls_ecp_keypair>();
		//ret = mbedtls_ecp_gen_keypair_base(&ecpGroup, &G, &keypair->d, &keypair->Q, mbedtls_ctr_drbg_random, &ctr_drbg);
		ret = mbedtls_ecp_gen_keypair(&ecpGroup, &keypair->d, &keypair->Q, mbedtls_ctr_drbg_random, &ctr_drbg);
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_GenKeys failed on generating keys: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			//mbedtls_ecp_point_free(&G);
			mbedtls_ecp_group_free(&ecpGroup);
			mbedtls_ctr_drbg_free( &ctr_drbg );
			mbedtls_entropy_free( &entropy );
			return false;
		}

		// d contains the PRIVATE key, Q contains the public key (Q.X is the required field).
		unsigned int keyBufSize;
		keyBufSize = mbedtls_mpi_size(&keypair->d);
		auto keyBuf = make_unique<unsigned char[]>( keyBufSize );
		mbedtls_mpi_write_binary(&keypair->d, keyBuf.get(), keyBufSize);
		relay.CURVE25519_PRIVATE_KEY = BriandUtils::ArrayToVector(keyBuf, keyBufSize);
		// The private key has no need to be reversed (my own use)

		//unsigned long int oLen;
		keyBufSize = mbedtls_mpi_size(&keypair->Q.X);
		keyBuf = make_unique<unsigned char[]>( keyBufSize );
		//keyBufSize = mbedtls_ecp_point_write_binary(&keypair->grp, &keypair->Q, MBEDTLS_ECP_PF_COMPRESSED, &oLen, keyBuf.get(), keyBufSize);
		mbedtls_mpi_write_binary(&keypair->Q.X, keyBuf.get(), keyBufSize);
		relay.CURVE25519_PUBLIC_KEY = BriandUtils::ArrayToVector(keyBuf, keyBufSize);

		// The public key sent to server as tor specifies, must be in little-endian format.
		// Mbedtls uses always big endian so must be reversed.
		ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_GenKeys using mbedtls, reversing the key for little endian format.\n");
		std::reverse(relay.CURVE25519_PUBLIC_KEY->begin(), relay.CURVE25519_PUBLIC_KEY->end());

		// Free
		mbedtls_ecp_keypair_free(keypair.get());
		//mbedtls_ecp_point_free(&G);
		mbedtls_ecp_group_free(&ecpGroup);
		mbedtls_ctr_drbg_free( &ctr_drbg );
		mbedtls_entropy_free( &entropy );

		return true;
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::ECDH_Curve25519_ComputeSharedSecret(const unique_ptr<vector<unsigned char>>& serverPublic, const unique_ptr<vector<unsigned char>>& privateKey) {
		// using mbedtls

		auto sharedSecret = make_unique<vector<unsigned char>>();

		// Initialize data structures needed
		unique_ptr<unsigned char[]> tempBuffer;
		int ret;
		mbedtls_ecp_point server_public;
		mbedtls_mpi private_key;
		mbedtls_mpi shared_secret;
		mbedtls_ecp_group ecpGroup;

		mbedtls_ecp_point_init(&server_public);
		mbedtls_ecp_group_init(&ecpGroup);
		mbedtls_mpi_init(&shared_secret);
		mbedtls_mpi_init(&private_key);

		// Curve25519 group initialization parameters
		mbedtls_ecp_group_load(&ecpGroup, MBEDTLS_ECP_DP_CURVE25519);

		// This:
		// char bb[32] = {0x00};
		// unsigned long int bbs;
		// mbedtls_mpi_write_string(&ecpGroup.G.X, 16, bb, 32, &bbs);
		// printf("Gx = %s\n", bb);
		// Gives output => Gx = 0x09 (big endian!)
		// So default params ok!
		// But that means also that mbedtls implementation works with REVERSE order!!

		// WARNING: mbedtls uses big endian format for computation but the tor protocol
		// exchanged keys are always in little endian so must be reversed!
		// (too many time spent on understanding why never work)

		// Set private key 
		// no need to reverse!

		ret = mbedtls_mpi_read_binary(&private_key, privateKey->data(), privateKey->size());

		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_ComputeSharedSecret failed to read private key: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ecp_group_free(&ecpGroup);
			mbedtls_mpi_free(&shared_secret);
			mbedtls_mpi_free(&private_key);
			mbedtls_ecp_point_free(&server_public);
			return std::move(sharedSecret);
		}

		// Public key received (only X must be filled!)
		// this must be reversed to compute secret
		auto tempV = make_unique<vector<unsigned char>>();
		tempV->insert(tempV->begin(), serverPublic->begin(), serverPublic->end());
		std::reverse(tempV->begin(), tempV->end());

		ret = mbedtls_mpi_read_binary(&server_public.X, tempV->data(), serverPublic->size());
		tempV.reset();
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_ComputeSharedSecret failed to read public key: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ecp_group_free(&ecpGroup);
			mbedtls_mpi_free(&shared_secret);
			mbedtls_mpi_free(&private_key);
			mbedtls_ecp_point_free(&server_public);
			return std::move(sharedSecret);
		}

		// Ensure that this point is non-infinity
		mbedtls_mpi_lset(&server_public.Z, 1);

		// Perform the shared secret as EXP(serverpublic, privatekey) or, in curve25519 language the multiplication of serverpublic*privatekey
		ret = mbedtls_ecdh_compute_shared(&ecpGroup, &shared_secret, &server_public, &private_key, NULL, NULL);
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_ComputeSharedSecret failed to compute shared secret: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ecp_group_free(&ecpGroup);
			mbedtls_mpi_free(&shared_secret);
			mbedtls_mpi_free(&private_key);
			mbedtls_ecp_point_free(&server_public);
			return std::move(sharedSecret);
		}

		// Save the result
		unsigned int sharedSecretSize = mbedtls_mpi_size(&shared_secret);
		tempBuffer = BriandUtils::GetOneOldBuffer(sharedSecretSize);
		ret = mbedtls_mpi_write_binary(&shared_secret, tempBuffer.get(), sharedSecretSize);
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			ESP_LOGD(LOGTAG, "[DEBUG] ECDH_Curve25519_ComputeSharedSecret failed to write out the shared secret: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ecp_group_free(&ecpGroup);
			mbedtls_mpi_free(&shared_secret);
			mbedtls_mpi_free(&private_key);
			mbedtls_ecp_point_free(&server_public);
			return std::move(sharedSecret);
		}

		// Free
		mbedtls_ecp_group_free(&ecpGroup);
		mbedtls_mpi_free(&shared_secret);
		mbedtls_mpi_free(&private_key);
		mbedtls_ecp_point_free(&server_public);

		// Copy data
		sharedSecret->insert(sharedSecret->begin(), tempBuffer.get(), tempBuffer.get() + sharedSecretSize); // safe!
		tempBuffer.reset();

		// Reverse data to little endian format
		std::reverse(sharedSecret->begin(), sharedSecret->end());

		return std::move(sharedSecret);
	}

	bool BriandTorCryptoUtils::NtorHandshakeComplete(BriandTorRelay& relay) {

		// Check if fields are OK (should be but...)

		if (relay.CURVE25519_PRIVATE_KEY == nullptr) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete: error! Relay CURVE25519_PRIVATE_KEY is null!\n");
			return false;
		}
		if (relay.CURVE25519_PUBLIC_KEY == nullptr) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete: error! Relay CURVE25519_PUBLIC_KEY context is null!\n");
			return false;
		}
		if (relay.CREATED_EXTENDED_RESPONSE_SERVER_PK == nullptr) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete: error! CREATED_EXTENDED_RESPONSE_SERVER_PK context is null!\n");
			return false;
		}
		if (relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH == nullptr) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete: error! CREATED_EXTENDED_RESPONSE_SERVER_AUTH context is null!\n");
			return false;
		}

		// Ok, let's go

		/*
			In this section, define:

			H(x,t) as HMAC_SHA256 with message x and key t.
			H_LENGTH  = 32.
			ID_LENGTH = 20.
			G_LENGTH  = 32
			PROTOID   = "ntor-curve25519-sha256-1"
			t_mac     = PROTOID | ":mac"
			t_key     = PROTOID | ":key_extract"
			t_verify  = PROTOID | ":verify"
			MULT(a,b) = the multiplication of the curve25519 point 'a' by the
						scalar 'b'.
			G         = The preferred base point for curve25519 ([9])
			KEYGEN()  = The curve25519 key generation algorithm, returning
						a private/public keypair.
			m_expand  = PROTOID | ":key_expand"
			KEYID(A)  = A
		*/

		// The "|" operator is a simple concatenation of the bytes

		//constexpr unsigned int G_LENGTH = 32;
		//constexpr unsigned int H_LENGTH = 32;
		string protoid_string = "ntor-curve25519-sha256-1";

		// using mbedtls works better the old-buffer version ....
		auto PROTOID = BriandUtils::HexStringToVector("", protoid_string);
		auto t_mac = BriandUtils::HexStringToVector("", protoid_string + ":mac");
		auto t_key = BriandUtils::HexStringToVector("", protoid_string + ":key_extract");
		auto t_verify = BriandUtils::HexStringToVector("", protoid_string + ":verify");
		auto m_expand = BriandUtils::HexStringToVector("", protoid_string + ":key_expand");
		auto ntorKeyVec = BriandTorCryptoUtils::Base64Decode(*relay.descriptorNtorOnionKey.get());
		auto fingerprintVector = BriandUtils::HexStringToVector(*relay.fingerprint.get(), "");

		// WARNING: mbedtls uses big endian format for computation but the tor protocol
		// exchanged keys are always in little endian so must be reversed!
		// (too many time spent on understanding why never work)

		/*
			The server's handshake reply is:

			SERVER_PK   Y                       [G_LENGTH bytes]
			AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
		
			and computes:
			secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
		*/

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] X = My Curve25519 public key: ");
			BriandUtils::PrintByteBuffer(*relay.CURVE25519_PUBLIC_KEY.get());
			printf("[DEBUG] x = My Curve25519 private key: ");
			BriandUtils::PrintByteBuffer(*relay.CURVE25519_PRIVATE_KEY.get());
			printf("[DEBUG] B = Relay's NTOR key: ");
			BriandUtils::PrintByteBuffer(*ntorKeyVec.get());
			printf("[DEBUG] Y = Relay's public key: ");
			BriandUtils::PrintByteBuffer(*relay.CREATED_EXTENDED_RESPONSE_SERVER_PK.get());
			printf("[DEBUG] ID = Relay's fingerprint: %s\n", relay.fingerprint->c_str());
			printf("[DEBUG] Relay's AUTH: ");
			BriandUtils::PrintByteBuffer(*relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH.get());
			printf("[DEBUG] PROTOID: ");
			BriandUtils::PrintByteBuffer(*PROTOID.get());
		}

		auto secret_input = make_unique<vector<unsigned char>>();

		// EXP(Y,x)
		auto tempVector = BriandTorCryptoUtils::ECDH_Curve25519_ComputeSharedSecret(relay.CREATED_EXTENDED_RESPONSE_SERVER_PK, relay.CURVE25519_PRIVATE_KEY);
		if (tempVector->size() == 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete: shared secret failed to compute: EXP(Y,x)!\n");
			return false;
		}
		
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] NtorHandshakeComplete: EXP(Y,x) = ");
			BriandUtils::PrintByteBuffer(*tempVector.get());
		}

		// Append EXP(Y,x)
		secret_input->insert(secret_input->end(), tempVector->begin(), tempVector->end());
		tempVector.reset();

		// EXP(B,x)
		tempVector = BriandTorCryptoUtils::ECDH_Curve25519_ComputeSharedSecret(ntorKeyVec, relay.CURVE25519_PRIVATE_KEY);
		if (tempVector->size() == 0) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete: shared secret failed to compute: EXP(B,x)!\n");
			return false;
		}

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] NtorHandshakeComplete: EXP(B,x) = ");
			BriandUtils::PrintByteBuffer(*tempVector.get());
		}
		
		// Append EXP(B,x)
		secret_input->insert(secret_input->end(), tempVector->begin(), tempVector->end());
		tempVector.reset();

		// Reset ntor key to NBO
		//std::reverse(ntorKeyVec->begin(), ntorKeyVec->end());

		// Append the fingerprint (ID)
		secret_input->insert(secret_input->end(), fingerprintVector->begin(), fingerprintVector->end());
		// Append the ntorKey (B)
		secret_input->insert(secret_input->end(), ntorKeyVec->begin(), ntorKeyVec->end());
		// Append X (my public key)
		secret_input->insert(secret_input->end(), relay.CURVE25519_PUBLIC_KEY->begin(), relay.CURVE25519_PUBLIC_KEY->end());
		// Append Y (relay's public key)
		secret_input->insert(secret_input->end(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->begin(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->end());
		// Append PROTOID
		secret_input->insert(secret_input->end(), PROTOID->begin(), PROTOID->end());

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG)  {
			printf("[DEBUG] NtorHandshakeComplete (complete) secret_input: ");
			BriandUtils::PrintByteBuffer(*secret_input.get(), secret_input->size(), secret_input->size());
		}

		/*	KEY_SEED = H(secret_input, t_key) */

		relay.KEYSEED = GetDigest_HMAC_SHA256(secret_input, t_key);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG)  {
			printf("[DEBUG] NtorHandshakeComplete KEYSEED: ");
			BriandUtils::PrintByteBuffer(*relay.KEYSEED.get(), relay.KEYSEED->size(), relay.KEYSEED->size());
		}

		/* verify = H(secret_input, t_verify) */

		auto verify = GetDigest_HMAC_SHA256(secret_input, t_verify);

		/* auth_input = verify | ID | B | Y | X | PROTOID | "Server" */
		
		auto auth_input = make_unique<vector<unsigned char>>();
		auth_input->insert(auth_input->end(), verify->begin(), verify->end());
		auth_input->insert(auth_input->end(), fingerprintVector->begin(), fingerprintVector->end());
		auth_input->insert(auth_input->end(), ntorKeyVec->begin(), ntorKeyVec->end());
		auth_input->insert(auth_input->end(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->begin(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->end());
		auth_input->insert(auth_input->end(), relay.CURVE25519_PUBLIC_KEY->begin(), relay.CURVE25519_PUBLIC_KEY->end());
		auth_input->insert(auth_input->end(), PROTOID->begin(), PROTOID->end());
		auto serverStringVector = BriandUtils::HexStringToVector("", "Server");
		auth_input->insert(auth_input->end(), serverStringVector->begin(), serverStringVector->end());

		/* The client verifies that AUTH == H(auth_input, t_mac). */
		auto auth_verify = GetDigest_HMAC_SHA256(auth_input, t_mac);
		if (auth_verify->size() != relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size()) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete Error, AUTH size and H(auth_input, t_mac) size does not match!\n");
			return false;
		}
		if (!std::equal(auth_verify->begin(), auth_verify->end(), relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH->begin())) {
			ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete Error, AUTH and H(auth_input, t_mac) not matching!\n");
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] NtorHandshakeComplete Relay response to CREATE2/EXTEND2 verified (success).\n");
	
		/*
			The client then checks Y is in G^* =======>>>> Both parties check that none of the EXP() operations produced the 
			point at infinity. [NOTE: This is an adequate replacement for checking Y for group membership, if the group is curve25519.]
		*/

		// This is satisfied when Z is set to 1 (see ECDH_Curve25519_ComputeSharedSecret function body)
		// Would throw error if infinity

		/* 
			Both parties now have a shared value for KEY_SEED.  They expand this
			into the keys needed for the Tor relay protocol, using the KDF
			described in 5.2.2 and the tag m_expand. 

			[...]

			
			For newer KDF needs, Tor uses the key derivation function HKDF from
			RFC5869, instantiated with SHA256.  (This is due to a construction
			from Krawczyk.)  The generated key material is:

				K = K_1 | K_2 | K_3 | ...

				Where H(x,t) is HMAC_SHA256 with value x and key t
					and K_1     = H(m_expand | INT8(1) , KEY_SEED )
					and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
					and m_expand is an arbitrarily chosen value,
					and INT8(i) is a octet with the value "i".

			In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
			salt == t_key, and IKM == secret_input.
		*/

		// Clear and simple:

		ESP_LOGD(LOGTAG, "[DEBUG] Generating keys with HKDF.\n");

		unsigned short KEY_LEN = 16;
	   	unsigned short HASH_LEN = 20;
		unsigned short DIGEST_LEN = 32; // TODO : did not found any reference to DIGEST_LEN size, suppose 32 with sha256
		unsigned short EXTRACT_TOTAL_SIZE = HASH_LEN+HASH_LEN+KEY_LEN+KEY_LEN+DIGEST_LEN;

		// Unfortunately ESP32 mbedtls could have HKDF disabled.
		// Could be enabled with the menuconfig however i wrote a function if not activated to avoid
		// compilation errors.
		
		#ifdef MBEDTLS_HKDF_C
		
		auto hkdfBuffer = BriandUtils::GetOneOldBuffer(EXTRACT_TOTAL_SIZE);

		mbedtls_hkdf(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			t_key->data(), t_key->size(), 
			secret_input->data(), secret_input->size(), 
			m_expand->data(), m_expand->size(), 
			hkdfBuffer.get(), EXTRACT_TOTAL_SIZE
		);

		auto hkdf = BriandUtils::ArrayToVector(hkdfBuffer, EXTRACT_TOTAL_SIZE);	
		
		#else

		auto hkdf = BriandTorCryptoUtils::Get_HKDF(m_expand, relay.KEYSEED, EXTRACT_TOTAL_SIZE); 
		
		#endif

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] HKDF expansion for keys: ");
			BriandUtils::PrintByteBuffer(*hkdf.get());
		}

		/*
			When used in the ntor handshake, the first HASH_LEN bytes form the
			forward digest Df; the next HASH_LEN form the backward digest Db; the
			next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
			DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
			hidden service protocol.  Excess bytes from K are discarded.
   		*/
		
		// Release some unused memory
		PROTOID.reset();
		t_mac.reset();
		t_key.reset();
		t_verify.reset();
		m_expand.reset();
		ntorKeyVec.reset();
		fingerprintVector.reset();
		secret_input.reset();
		verify.reset();
		serverStringVector.reset();
		auth_input.reset();
		auth_verify.reset();

		// This field is updated with SHA1 hash when relay cells are sent but not finalized itself!
	   	relay.KEY_ForwardDigest_Df = make_unique<mbedtls_md_context_t>();
		mbedtls_md_init(relay.KEY_ForwardDigest_Df.get());
		mbedtls_md_setup(relay.KEY_ForwardDigest_Df.get(), mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
		mbedtls_md_starts(relay.KEY_ForwardDigest_Df.get());
		mbedtls_md_update(relay.KEY_ForwardDigest_Df.get(), hkdf->data(), HASH_LEN);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Relay digest forward seed: ");
			BriandUtils::PrintByteBuffer(*hkdf.get(), 0, HASH_LEN);
		}

		hkdf->erase(hkdf->begin(), hkdf->begin() + HASH_LEN);

		// This field is updated with SHA1 hash when relay cells are received but not finalized itself!
		relay.KEY_BackwardDigest_Db = make_unique<mbedtls_md_context_t>();
		mbedtls_md_init(relay.KEY_BackwardDigest_Db.get());
		mbedtls_md_setup(relay.KEY_BackwardDigest_Db.get(), mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
		mbedtls_md_starts(relay.KEY_BackwardDigest_Db.get());
		mbedtls_md_update(relay.KEY_BackwardDigest_Db.get(), hkdf->data(), HASH_LEN);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Relay digest backward seed: ");
			BriandUtils::PrintByteBuffer(*hkdf.get(), 0, HASH_LEN);
		}

		hkdf->erase(hkdf->begin(), hkdf->begin() + HASH_LEN);

		relay.KEY_Forward_Kf = make_unique<vector<unsigned char>>();
		relay.KEY_Forward_Kf->insert(relay.KEY_Forward_Kf->begin(), hkdf->begin(), hkdf->begin() + KEY_LEN);
		hkdf->erase(hkdf->begin(), hkdf->begin() + KEY_LEN);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] KEY forward: ");
			BriandUtils::PrintByteBuffer(*relay.KEY_Forward_Kf.get());
		}

		relay.KEY_Backward_Kb = make_unique<vector<unsigned char>>();
		relay.KEY_Backward_Kb->insert(relay.KEY_Backward_Kb->begin(), hkdf->begin(), hkdf->begin() + KEY_LEN);
		hkdf->erase(hkdf->begin(), hkdf->begin() + KEY_LEN);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] KEY backward: ");
			BriandUtils::PrintByteBuffer(*relay.KEY_Backward_Kb.get());
		}

		relay.KEY_HiddenService_Nonce = make_unique<vector<unsigned char>>();
		relay.KEY_HiddenService_Nonce->insert(relay.KEY_HiddenService_Nonce->begin(), hkdf->begin(), hkdf->begin() + DIGEST_LEN);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] HS nonce: ");
			BriandUtils::PrintByteBuffer(*relay.KEY_HiddenService_Nonce.get());
		}

		hkdf.reset();
		
		// Setup AES context (keysize must be specified in bits)
		esp_aes_init(relay.AES_ForwardContext.get());
		esp_aes_setkey(relay.AES_ForwardContext.get(), relay.KEY_Forward_Kf->data(), relay.KEY_Forward_Kf->size() * 8);
		esp_aes_init(relay.AES_BackwardContext.get());
		esp_aes_setkey(relay.AES_BackwardContext.get(), relay.KEY_Backward_Kb->data(), relay.KEY_Backward_Kb->size() * 8);

		ESP_LOGD(LOGTAG, "[DEBUG] All done!\n");

		return true;
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::AES128CTR_Encrypt(const unique_ptr<vector<unsigned char>>& content, BriandTorRelay& relay) {
		auto outBuffer = make_unique<unsigned char[]>(content->size());

		// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
		esp_aes_crypt_ctr(
			relay.AES_ForwardContext.get(), 
			content->size(), 
			&relay.AES_ForwardNonceOffset, 
			relay.AES_ForwardNonceCounter, 
			relay.AES_ForwardIV, 
			content->data(), 
			outBuffer.get()
		);

		return std::move( BriandUtils::ArrayToVector(outBuffer, content->size()) );
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::AES128CTR_Decrypt(const unique_ptr<vector<unsigned char>>& content, BriandTorRelay& relay) {
		auto outBuffer = make_unique<unsigned char[]>(content->size());

		// Decrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
		esp_aes_crypt_ctr(
			relay.AES_BackwardContext.get(), 
			content->size(), 
			&relay.AES_BackwardNonceOffset, 
			relay.AES_BackwardNonceCounter, 
			relay.AES_BackwardIV, 
			content->data(), 
			outBuffer.get()
		);

		return std::move( BriandUtils::ArrayToVector(outBuffer, content->size()) );
	}


}