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

#include <Arduino.h>

#include "BriandTorCryptoUtils.hxx"

#include <iostream>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstring>

#include <WiFiClientSecure.h>

/* mbedTLS library for SSL / SHA / TLS / RSA */
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/pk.h>
#include <mbedtls/base64.h>
#include <mbedtls/hkdf.h>

/* LibSodium found for Ed25519 signatures! It's on framwork :-D */
#include <sodium.h>

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
		auto inputRaw = BriandUtils::VectorToArray(input);

		if (DEBUG) Serial.printf("[DEBUG] SHA256 Raw message to encode: ");
		BriandUtils::PrintOldStyleByteBuffer(inputRaw.get(), input->size(), input->size(), input->size());
		
		// Using mbedtls_md() not working as expected!!

		auto mdCtx = make_unique<mbedtls_md_context_t>();

		mbedtls_md_setup(mdCtx.get(), mdInfo, 0);
		mbedtls_md_starts(mdCtx.get());
		mbedtls_md_update(mdCtx.get(), inputRaw.get(), input->size());
		mbedtls_md_finish(mdCtx.get(), hashedMessageRaw.get());

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
		
		if (DEBUG) Serial.printf("[DEBUG] SHA256 Raw output: ");
		BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size, mdInfo->size);

		auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

		// Free (MUST!)
		mbedtls_md_free(mdCtx.get());

		return std::move(digest);
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::GetDigest_HMAC_SHA256(const unique_ptr<vector<unsigned char>>& input, const unique_ptr<vector<unsigned char>>& key) {	
		// Using mbedtls

		auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

		auto hashedMessageRaw = BriandUtils::GetOneOldBuffer(mdInfo->size);
		auto inputRaw = BriandUtils::VectorToArray(input);
		auto keyRaw = BriandUtils::VectorToArray(key);

		if (DEBUG) Serial.printf("[DEBUG] HMAC-SHA256 Raw message to encode: ");
		BriandUtils::PrintOldStyleByteBuffer(inputRaw.get(), input->size(), input->size(), input->size());
		
		// Using mbedtls_md() not working as expected!!

		auto mdCtx = make_unique<mbedtls_md_context_t>();

		mbedtls_md_setup(mdCtx.get(), mdInfo, 1); // last 1: specify hmac
		mbedtls_md_hmac_starts(mdCtx.get(), keyRaw.get(), key->size());
		mbedtls_md_hmac_update(mdCtx.get(), inputRaw.get(), input->size());
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
		
		if (DEBUG) Serial.printf("[DEBUG] HMAC-SHA256 Raw output: ");
		BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size, mdInfo->size);

		auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

		// Free (MUST!)
		mbedtls_md_free(mdCtx.get());

		return std::move(digest);
	}

	bool BriandTorCryptoUtils::CheckSignature_RSASHA256(const unique_ptr<vector<unsigned char>>& message, const unique_ptr<vector<unsigned char>>& x509DerCertificate, const unique_ptr<vector<unsigned char>>& signature) {
		// Using mbedtls

		// First, calculate hash SHA256 of the message
		auto messageHash = BriandUtils::VectorToArray( GetDigest_SHA256(message) );
		constexpr unsigned short DIGEST_SIZE = 32;

		// Structures needed
		mbedtls_x509_crt rsaIde;
		mbedtls_x509_crt_init(&rsaIde);

		// Extract the PK from the certificate

		auto certBuffer = BriandUtils::VectorToArray(x509DerCertificate);

		if ( mbedtls_x509_crt_parse(&rsaIde, certBuffer.get(), x509DerCertificate->size()) != 0) {
			Serial.println("[DEBUG] CheckSignature RSA/SHA256: failed to parse certificate.");
			
			// Free
			mbedtls_x509_crt_free(&rsaIde);
			return false;
		}

		// Prepare other buffers neeeded
		auto signatureBuffer = BriandUtils::VectorToArray(signature);

		// Thanks a lot @gilles-peskine-arm for resolving the problem! ( https://github.com/ARMmbed/mbedtls/issues/4400 )
		// Using MBEDTLS_MD_NONE because this is raw data, and this function expects a signature with added information data
		// about the MD used.
		int verifyResult = mbedtls_pk_verify(&rsaIde.pk, MBEDTLS_MD_NONE, messageHash.get(), DIGEST_SIZE, signatureBuffer.get(), signature->size());

		if (verifyResult != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(verifyResult, reinterpret_cast<char*>(errBuf.get()), 128);

			Serial.printf("[DEBUG] CheckSignature RSA/SHA256 signature INVALID: %s\n", reinterpret_cast<char*>(errBuf.get()));
			
			// Free
			mbedtls_x509_crt_free(&rsaIde);
			return false;
		}

		// Free (MUST!)
		mbedtls_x509_crt_free(&rsaIde);

		Serial.printf("[DEBUG] CheckSignature RSA/SHA256 signature valid.\n");

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
		auto tempBuffer = BriandUtils::VectorToArray(x509CACertificate);

		// Parse CA and add to chain
		if (mbedtls_x509_crt_parse(&chain, tempBuffer.get(), x509CACertificate->size()) != 0) {
			if (DEBUG) Serial.printf("[DEBUG] X509Validate: failed to parse CA certificate.\n");

			// free
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return false;
		}	

		// Parse CA again but add to ROOTCA chain to verify against
		mbedtls_x509_crt_parse(&root_ca, tempBuffer.get(), x509CACertificate->size());

		// Reset buffer and parse the peer (this) certificate

		tempBuffer = BriandUtils::VectorToArray(x509PeerCertificate);

		// Parse Peer and add to chain
		if ( mbedtls_x509_crt_parse(&chain, tempBuffer.get(), x509PeerCertificate->size()) != 0) {
			if (DEBUG) Serial.printf("[DEBUG] X509Validate: failed to parse peer certificate.\n");

			// free
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return false;
		}	

		// Not need anymore the buffer, save RAM
		tempBuffer.reset();

		// Validate
		// to see validation results the verify callback could be added.
		unsigned int verification_flags;
		
		if (mbedtls_x509_crt_verify_with_profile(&chain, &root_ca, NULL,  &profile, NULL, &verification_flags, NULL, NULL) != 0) {
			if (DEBUG) {
				tempBuffer = BriandUtils::GetOneOldBuffer(256 + 1);
				mbedtls_x509_crt_verify_info( reinterpret_cast<char*>(tempBuffer.get()), 256, "", verification_flags);
				Serial.printf("[DEBUG] X509Validate failed because %s\n", reinterpret_cast<const char*>(tempBuffer.get()));
			} 

			// free 
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return false;
		}

		if (DEBUG) Serial.printf("[DEBUG] X509Validate: success.\n");

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
			if (DEBUG) Serial.println("[DEBUG] CheckSignature Ed25519 Error on sodium_init()");
			return false;
		}

		// Prepare buffers
		auto messageBuffer = BriandUtils::VectorToArray(message);
		auto pkBuffer = BriandUtils::VectorToArray(ed25519PK);
		auto signatureBuffer = BriandUtils::VectorToArray(signature);

		if (crypto_sign_verify_detached(signatureBuffer.get(), messageBuffer.get(), message->size(), pkBuffer.get()) != 0) {
			if (DEBUG) Serial.println("[DEBUG] CheckSignature Ed25519 signature is not valid.");
			return false;
		}

		if (DEBUG) Serial.printf("[DEBUG] CheckSignature Ed25519 signature valid.\n");

		return true;
	}

	unique_ptr<vector<unsigned char>> BriandTorCryptoUtils::Base64Decode(const string& input) {
		// using mbedtls
		
		auto output = make_unique<vector<unsigned char>>();
		unsigned int outSize;
		
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

	bool BriandTorCryptoUtils::ECDH_CURVE25519_GenKeys(BriandTorRelay& relay) {
		// using mbedtls

		// Prepare relay
		if (relay.ECDH_CURVE25519_CLIENT_TO_SERVER != nullptr)
			relay.ECDH_CURVE25519_CLIENT_TO_SERVER.reset();
		if (relay.ECDH_CURVE25519_CONTEXT != nullptr)
			relay.ECDH_CURVE25519_CONTEXT.reset();

		relay.ECDH_CURVE25519_CLIENT_TO_SERVER = make_unique<vector<unsigned char>>();
		relay.ECDH_CURVE25519_CONTEXT = make_unique<mbedtls_ecdh_context>();

		// Structures needed
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;

		string pers = "ECDHGenKeys"; // TODO : randomize
		unsigned int ret;

		constexpr unsigned short CLIENT_TO_SERVER_SIZE = 32;
		auto clientToServer = make_unique<unsigned char[]>(CLIENT_TO_SERVER_SIZE);

		// Initialize structures
		mbedtls_ecdh_init( relay.ECDH_CURVE25519_CONTEXT.get() );
		mbedtls_ctr_drbg_init( &ctr_drbg );

		// Initialize random number generation

		mbedtls_entropy_init( &entropy );
		ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char*>(pers.c_str()), pers.length() );
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			if (DEBUG) Serial.printf("[DEBUG] ECDH_GenKeys failed initialize RNG: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ctr_drbg_free( &ctr_drbg );
			mbedtls_entropy_free( &entropy );
			return false;
		}

		// Initialize context and generate keypair with CURVE25519

		ret = mbedtls_ecp_group_load( &relay.ECDH_CURVE25519_CONTEXT->grp, MBEDTLS_ECP_DP_CURVE25519 );
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			if (DEBUG) Serial.printf("[DEBUG] ECDH_GenKeys failed ECP group loading: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ctr_drbg_free( &ctr_drbg );
			mbedtls_entropy_free( &entropy );
			return false;
		}
		
		// Gen public key
		ret = mbedtls_ecdh_gen_public( 
			&relay.ECDH_CURVE25519_CONTEXT->grp, 
			&relay.ECDH_CURVE25519_CONTEXT->d, 
			&relay.ECDH_CURVE25519_CONTEXT->Q, 
			mbedtls_ctr_drbg_random, &ctr_drbg 
		);
		if (ret != 0) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			if (DEBUG) Serial.printf("[DEBUG] ECDH_GenKeys failed public key generation: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ctr_drbg_free( &ctr_drbg );
			mbedtls_entropy_free( &entropy );
			return false;
		}

		// Write to string
		ret = mbedtls_mpi_write_binary( &relay.ECDH_CURVE25519_CONTEXT->Q.X, clientToServer.get(), CLIENT_TO_SERVER_SIZE );
		if( ret != 0 ) {
			// Error description
			auto errBuf = BriandUtils::GetOneOldBuffer(128 + 1);
			mbedtls_strerror(ret, reinterpret_cast<char*>(errBuf.get()), 128);
			if (DEBUG) Serial.printf("[DEBUG] ECDH_GenKeys failed public key generation: %s\n", reinterpret_cast<char*>(errBuf.get()));
			// Free
			mbedtls_ctr_drbg_free( &ctr_drbg );
			mbedtls_entropy_free( &entropy );
			return false;
		}

		relay.ECDH_CURVE25519_CLIENT_TO_SERVER = BriandUtils::ArrayToVector(clientToServer, CLIENT_TO_SERVER_SIZE);

		if (DEBUG) {
			Serial.printf("[DEBUG] ECDH_GenKeys success, computed: ");
			BriandUtils::PrintByteBuffer(*relay.ECDH_CURVE25519_CLIENT_TO_SERVER.get(), CLIENT_TO_SERVER_SIZE, CLIENT_TO_SERVER_SIZE);
		} 

		// Free
		mbedtls_ctr_drbg_free( &ctr_drbg );
		mbedtls_entropy_free( &entropy );

		return true;
	}

	bool BriandTorCryptoUtils::NtorHandshakeComplete(BriandTorRelay& relay) {
		// using mbedtls
		
		// Check if fields are OK (should be but...)
		if (relay.ECDH_CURVE25519_CONTEXT == nullptr) {
			Serial.println("[DEBUG] NtorHandshakeComplete: error! ECDH_CURVE25519_CONTEXT context is null!");
			return false;
		}
		if (relay.ECDH_CURVE25519_CLIENT_TO_SERVER == nullptr) {
			Serial.println("[DEBUG] NtorHandshakeComplete: error! ECDH_CURVE25519_CLIENT_TO_SERVER context is null!");
			return false;
		}
		if (relay.CREATED_EXTENDED_RESPONSE_SERVER_PK == nullptr) {
			Serial.println("[DEBUG] NtorHandshakeComplete: error! CREATED_EXTENDED_RESPONSE_SERVER_PK context is null!");
			return false;
		}
		if (relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH == nullptr) {
			Serial.println("[DEBUG] NtorHandshakeComplete: error! CREATED_EXTENDED_RESPONSE_SERVER_AUTH context is null!");
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

		constexpr unsigned int G_LENGTH = 32;
		constexpr unsigned int H_LENGTH = 32;
		string protoid_string = "ntor-curve25519-sha256-1";

		// using mbedtls works better the old-buffer version ....
		auto PROTOID = BriandUtils::HexStringToVector("", protoid_string);
		auto t_mac = BriandUtils::HexStringToVector("", protoid_string + ":mac");
		auto t_key = BriandUtils::HexStringToVector("", protoid_string + ":key_extract");
		auto t_verify = BriandUtils::HexStringToVector("", protoid_string + ":verify");
		unsigned int m_expand_size;
		auto m_expand = BriandUtils::HexStringToOldBuffer("", m_expand_size, protoid_string + ":key_expand");

		/*
			The server's handshake reply is:

			SERVER_PK   Y                       [G_LENGTH bytes]
			AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
		
			and computes:
			secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
		*/

		auto secret_input = make_unique<vector<unsigned char>>();

		// temporary common data
		unsigned int tempSize;
		unique_ptr<unsigned char[]> tempBuffer;
		mbedtls_mpi tempResult, tempIndex;

		// Needed for calculations
		mbedtls_mpi Y, x, B;
		
		// Initialize mpi with mbedtls
		mbedtls_mpi_init(&Y);
		mbedtls_mpi_init(&x);
		mbedtls_mpi_init(&B);
		mbedtls_mpi_init(&tempResult);
		mbedtls_mpi_init(&tempIndex);

		// Where B is the ntor onion key of the relay
		auto ntorKeyVec = Base64Decode(*relay.descriptorNtorOnionKey.get());
		mbedtls_mpi_read_binary(&B, reinterpret_cast<const unsigned char*>( BriandUtils::VectorToArray(ntorKeyVec).get() ), ntorKeyVec->size());
		// x is the client's private key generated previously (p field)
		mbedtls_mpi_copy(&x, (const mbedtls_mpi*)relay.ECDH_CURVE25519_CONTEXT->d.p);
		// and Y is in the relay response 
		mbedtls_mpi_read_binary(&Y, reinterpret_cast<const unsigned char*>( BriandUtils::VectorToArray(relay.CREATED_EXTENDED_RESPONSE_SERVER_PK).get() ), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->size());

		// Start with Y^x mbedtls has no direct exp function (only modular) so multiply 
		mbedtls_mpi_copy(&tempResult, &Y);
		mbedtls_mpi_copy(&tempIndex, &x);
		mbedtls_mpi_sub_int(&tempIndex, &tempIndex, 1); // the first (^1) has been made with copy
		while (mbedtls_mpi_cmp_int(&tempIndex, 0) > 0) {
			mbedtls_mpi_mul_mpi(&tempResult, &tempResult, &Y);
			mbedtls_mpi_sub_int(&tempIndex, &tempIndex, 1);
		}

		// Start to save bytes
		tempSize = mbedtls_mpi_size(&tempResult);
		tempBuffer = make_unique<unsigned char[]>( tempSize );
		mbedtls_mpi_write_binary(&tempResult, tempBuffer.get(), tempSize);
		secret_input->insert(secret_input->begin(), tempBuffer.get(), tempBuffer.get() + tempSize); // safe!
		tempBuffer.reset();
		tempSize = 0;

		// Now calculate B^x
		mbedtls_mpi_copy(&tempResult, &B);
		mbedtls_mpi_copy(&tempIndex, &x);
		mbedtls_mpi_sub_int(&tempIndex, &tempIndex, 1); // the first (^1) has been made with copy
		while (mbedtls_mpi_cmp_int(&tempIndex, 0) > 0) {
			mbedtls_mpi_mul_mpi(&tempResult, &tempResult, &B);
			mbedtls_mpi_sub_int(&tempIndex, &tempIndex, 1);
		}

		// Append bytes
		tempSize = mbedtls_mpi_size(&tempResult);
		tempBuffer = make_unique<unsigned char[]>( tempSize );
		mbedtls_mpi_write_binary(&tempResult, tempBuffer.get(), tempSize);
		secret_input->insert(secret_input->end(), tempBuffer.get(), tempBuffer.get() + tempSize); // safe!
		tempBuffer.reset();
		tempSize = 0;

		// Now free not anymore needed mpis
		mbedtls_mpi_free(&Y);
		mbedtls_mpi_free(&x);
		mbedtls_mpi_free(&B);
		mbedtls_mpi_free(&tempResult);
		mbedtls_mpi_free(&tempIndex);

		// Append the fingerprint (ID)
		auto fingerprintVector = BriandUtils::HexStringToVector(*relay.fingerprint.get(), "");
		secret_input->insert(secret_input->end(), fingerprintVector->begin(), fingerprintVector->end());
		// Append the ntorKey (B)
		secret_input->insert(secret_input->end(), ntorKeyVec->begin(), ntorKeyVec->end());
		// Append X (my public key)
		secret_input->insert(secret_input->end(), relay.ECDH_CURVE25519_CLIENT_TO_SERVER->begin(), relay.ECDH_CURVE25519_CLIENT_TO_SERVER->end());
		// Append Y (relay's public key)
		secret_input->insert(secret_input->end(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->begin(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->end());
		// Append PROTOID
		secret_input->insert(secret_input->end(), PROTOID->begin(), PROTOID->end());

		if (DEBUG)  {
			Serial.printf("[DEBUG] secret_input: ");
			BriandUtils::PrintByteBuffer(*secret_input.get(), secret_input->size(), secret_input->size());
		}

		/*	KEY_SEED = H(secret_input, t_key) */

		relay.KEYSEED = GetDigest_HMAC_SHA256(secret_input, t_key);

		if (DEBUG)  {
			Serial.printf("[DEBUG] KEYSEED: ");
			BriandUtils::PrintByteBuffer(*relay.KEYSEED.get(), relay.KEYSEED->size(), relay.KEYSEED->size());
		}

		/* verify = H(secret_input, t_verify) */

		auto verify = GetDigest_HMAC_SHA256(secret_input, t_verify);

		/* auth_input = verify | ID | B | Y | X | PROTOID | "Server" */
		
		auto auth_input = make_unique<vector<unsigned char>>();
		auth_input->insert(auth_input->begin(), verify->begin(), verify->end());
		auth_input->insert(auth_input->end(), fingerprintVector->begin(), fingerprintVector->end());
		auth_input->insert(auth_input->end(), ntorKeyVec->begin(), ntorKeyVec->end());
		auth_input->insert(auth_input->end(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->begin(), relay.CREATED_EXTENDED_RESPONSE_SERVER_PK->end());
		auth_input->insert(auth_input->end(), relay.ECDH_CURVE25519_CLIENT_TO_SERVER->begin(), relay.ECDH_CURVE25519_CLIENT_TO_SERVER->end());
		auth_input->insert(auth_input->end(), PROTOID->begin(), PROTOID->end());
		auto serverStringVector = BriandUtils::HexStringToVector("", "Server");
		auth_input->insert(auth_input->end(), serverStringVector->begin(), serverStringVector->end());

		/* The client verifies that AUTH == H(auth_input, t_mac). */
		auto auth_verify = GetDigest_HMAC_SHA256(auth_input, t_mac);
		if (auth_verify->size() != relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size()) {
			Serial.println("[DEBUG] Error, AUTH size and H(auth_input, t_mac) size does not match!");
			return false;
		}
		if (!std::equal(auth_verify->begin(), auth_verify->end(), relay.CREATED_EXTENDED_RESPONSE_SERVER_AUTH->begin())) {
			Serial.println("[DEBUG] Error, AUTH and H(auth_input, t_mac) not matching!");
			return false;
		}

		if (DEBUG) Serial.println("[DEBUG] Relay response to CREATE2/EXTEND2 verified (success).");
	
		/*
			The client then checks Y is in G^* =======>>>> Both parties check that none of the EXP() operations produced the 
			point at infinity. [NOTE: This is an adequate replacement for checking Y for group membership, if the group is curve25519.]
		*/

		//
		// TODO
		// 

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

		if (DEBUG) Serial.print("[DEBUG] Generating keys with HKDF...");

		auto hkdfBuffer = BriandUtils::GetOneOldBuffer(255);
		mbedtls_hkdf(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			BriandUtils::VectorToArray(t_key).get(), t_key->size(), 
			BriandUtils::VectorToArray(secret_input).get(), secret_input->size(), 
			m_expand.get(), m_expand_size, 
			hkdfBuffer.get(), 32
		);
		
		/*
			When used in the ntor handshake, the first HASH_LEN bytes form the
			forward digest Df; the next HASH_LEN form the backward digest Db; the
			next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
			DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
			hidden service protocol.  Excess bytes from K are discarded.
   		*/

			
		
	   if (DEBUG) Serial.print("done!\n");

		return true;
	}

}