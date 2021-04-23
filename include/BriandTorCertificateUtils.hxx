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

#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstring>

/* mbedTLS library for SSL / SHA / TLS / RSA */
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/pk.h>


/* LibSodium found for Ed25519 signatures! It's on framwork :-D */
#include <sodium.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"

/* This class contains utility methods to perform hashing and certificate validation, depending on the chosen implementation/library */

using namespace std;

namespace Briand {
	class BriandTorCertificateUtils {
		public:

		/**
		 * Method perform SHA256 digest on the input bytes.
		 * @param input input bytes
		 * @return Pointer to vector containing hash.
		*/
		static unique_ptr<vector<unsigned char>> GetDigest_SHA256(const unique_ptr<vector<unsigned char>>& input) {	
			// Using mbedtls

			auto mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

			auto hashedMessageRaw = BriandUtils::GetOneOldBuffer(mdInfo->size);
			auto inputRaw = BriandUtils::VectorToArray(input);

			if (DEBUG) Serial.printf("[DEBUG] SHA256 Raw message to encode: ");
			BriandUtils::PrintOldStyleByteBuffer(inputRaw.get(), input->size(), input->size()+1, input->size());
			
			// Using mbedtls_md() not working as expected!!

			mbedtls_md_context_t mdCtx;
			mbedtls_md_setup(&mdCtx, mdInfo, 0);
			mbedtls_md_starts(&mdCtx);
			mbedtls_md_update(&mdCtx, inputRaw.get(), input->size());
			mbedtls_md_finish(&mdCtx, hashedMessageRaw.get());
			
			if (DEBUG) Serial.printf("[DEBUG] SHA256 Raw output: ");
			BriandUtils::PrintOldStyleByteBuffer(hashedMessageRaw.get(), mdInfo->size, mdInfo->size+1, mdInfo->size);

			auto digest = BriandUtils::ArrayToVector(hashedMessageRaw, mdInfo->size);

			// Free (MUST)
			// TODO : verify exception
			//mbedtls_md_free(&mdCtx);
			
			return std::move(digest);
		}

		/**
		 * Method verifies SHA256 RSA PKCS#1 signature
		 * @param message The message (raw data)
		 * @param x509DerCertificate The DER-encoded X.509 certificate containing the PublicKey (PK) to check signature
		 * @param signature Signature bytes
		 * @return true if valid, false instead 
		*/
		static bool CheckSignature_RSASHA256(const unique_ptr<vector<unsigned char>>& message, const unique_ptr<vector<unsigned char>>& x509DerCertificate, const unique_ptr<vector<unsigned char>>& signature) {
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
				auto errBuf = BriandUtils::GetOneOldBuffer(256 + 1);
				mbedtls_strerror(verifyResult, reinterpret_cast<char*>(errBuf.get()), 256);

				Serial.printf("[DEBUG] CheckSignature RSA/SHA256 signature INVALID: %s\n", reinterpret_cast<char*>(errBuf.get()));
				
				// Free
				mbedtls_x509_crt_free(&rsaIde);
				return false;
			}

			// Free (MUST!)
			mbedtls_x509_crt_free(&rsaIde);

			return true;
		}	

		/**
		 * Method verifies a X.509 certificate against the provided root certificate
		 * @param x509PeerCertificate The  .509 peer certificate (DER endoded raw bytes or PEM-Encoded but with added null-termination)
		 * @param x509CACertificate The X.509 CA certificate (DER endoded raw bytes or PEM-Encoded but with added null-termination)
		 * @return true if valid, false instead 
		*/
		static bool X509Validate(const unique_ptr<vector<unsigned char>>& x509PeerCertificate, const unique_ptr<vector<unsigned char>>& x509CACertificate) {
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
	};
}