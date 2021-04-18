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

#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand {
	

	/**
	 * This class describes and keeps information about a relay certificate obtained with CERTS cell
	*/
	class BriandTorCertificate {
		public:

		/*
			Relevant certType values are:
				1: Link key certificate certified by RSA1024 identity
				2: RSA1024 Identity certificate, self-signed.
				3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.
				4: Ed25519 signing key, signed with identity key.
				5: TLS link certificate, signed with ed25519 signing key.
				6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.
				7: Ed25519 identity, signed with RSA identity.

			The certificate format for certificate types 1-3 is DER encoded
			X509.  For others, the format is as documented in cert-spec.txt.
			Note that type 7 uses a different format from types 4-6.
		*/

		static const unsigned char MAX_CERT_VALUE = 7;

		enum CertType : unsigned char {
			LinkKeyWithRSA1024 = 1,
			RSA1024_Identity_Self_Signed = 2,
			RSA_1024_AUTHENTICATE_Cell_Link = 3,
			Ed25519_Signing_Key = 4,
			TLS_Link = 5,
			Ed25519_AUTHENTICATE_Cell_key = 6,
			Ed25519_Identity = 7
		};

		Briand::BriandTorCertificate::CertType Type;
		unique_ptr<vector<unsigned char>> Contents;

		BriandTorCertificate() {
			this->Contents = make_unique<vector<unsigned char>>();
		}

		// Copy constructor to avoid error "use of deleted function..."
		BriandTorCertificate(const BriandTorCertificate& other) {
			this->Contents = make_unique<vector<unsigned char>>();
			this->Contents->insert(this->Contents->begin(), other.Contents->begin(), other.Contents->end());
			this->Type = other.Type;
		}

		~BriandTorCertificate() {
			this->Contents.release();
		}

		/**
		 * Method return string containing certificate type and raw bytes 
		 * @return string with short info
		*/
		string GetCertificateShortInfo() {
			ostringstream builder;
			builder << "Certificate Type: " << static_cast<unsigned short>(this->Type) << "/";
			switch (this->Type)
			{
				case CertType::Ed25519_AUTHENTICATE_Cell_key:
					builder << "Ed25519_AUTHENTICATE_Cell_key";
					break;
				case CertType::Ed25519_Identity:
					builder << "Ed25519_Identity";
					break;
				case CertType::Ed25519_Signing_Key:
					builder << "Ed25519_Signing_Key";
					break;
				case CertType::LinkKeyWithRSA1024:
					builder << "LinkKeyWithRSA1024";
					break;
				case CertType::RSA1024_Identity_Self_Signed:
					builder << "RSA1024_Identity_Self_Signed";
					break;
				case CertType::RSA_1024_AUTHENTICATE_Cell_Link:
					builder << "RSA_1024_AUTHENTICATE_Cell_Link";
					break;
				case CertType::TLS_Link:
					builder << "TLS_Link";
					break;
				default:
					builder << "Unknown value of " << dec << static_cast<short>( this->Type );
					break;
			}

			builder << "Size: " << dec << this->Contents->size() << " bytes";
			builder << " Content bytes: ";

			for (unsigned int i = 0; i<this->Contents->size(); i++)
				builder << hex << std::setfill('0') << std::setw(2) << std::uppercase << static_cast<unsigned short>(this->Contents->at(i));

			return builder.str();
		}
	
		/**
		 * Method to check if certificate is valid against the specified root ca (identity).
		 * Works for RSA and Curve using Mbedtls library within ESP32. Use a lower profile to check certificate.
		 * @param rootCA The root CA for signature verify
		 * @return true if valid, false if not.
		*/
		bool isValid(BriandTorCertificate& rootCA) {

			if (this->Type == LinkKeyWithRSA1024) {
				if (rootCA.Type != RSA1024_Identity_Self_Signed) {
					if (DEBUG) Serial.println("[DEBUG] Certificate validation: must be used RSA1024_Identity_Self_Signed to validate LinkKeyWithRSA1024");
					return false;
				}

				// Buffers needed
				unique_ptr<unsigned char[]> tempBuffer = nullptr;
				unsigned int caSize = rootCA.Contents->size() + 1; // +1 because MUST be null-terminated
				unsigned int peerSize = this->Contents->size() + 1;

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
				profile.rsa_min_bitlen = 1024;

				// Start to parse the CA and add it to chain
				// CA MUST BE THE FIRST IN THE CHAIN!!!
				tempBuffer = BriandUtils::GetOneOldBuffer( caSize ); // MUST be zero-init

				// Copy contents
				std::copy(rootCA.Contents->begin(), rootCA.Contents->end(), tempBuffer.get() );

				// Parse CA and add to chain
				if ( mbedtls_x509_crt_parse(&chain, reinterpret_cast<const unsigned char*>(tempBuffer.get()), caSize) != 0) {
					if (DEBUG) Serial.println("[DEBUG] Certificate validation: failed to parse rootCA.");

					// free
					mbedtls_x509_crt_free(&chain);
					mbedtls_x509_crt_free(&root_ca);

					return false;
				}	

				// Parse CA again but add to ROOTCA chain to verify against
				mbedtls_x509_crt_parse(&root_ca, reinterpret_cast<const unsigned char*>(tempBuffer.get()), caSize);

				// Reset buffer and parse the peer (this) certificate

				tempBuffer = BriandUtils::GetOneOldBuffer( peerSize ); // MUST be zero-init

				// Copy contents
				std::copy(this->Contents->begin(), this->Contents->end(), tempBuffer.get() );

				// Parse Peer and add to chain
				if ( mbedtls_x509_crt_parse(&chain, reinterpret_cast<const unsigned char*>(tempBuffer.get()), peerSize) != 0) {
					if (DEBUG) Serial.println("[DEBUG] Certificate validation: failed to parse peer.");

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
						mbedtls_x509_crt_verify_info(vbuf, 256,"", verification_flags);
						Serial.printf("[DEBUG] Certificate validation: failed because %s\n", vbuf);
					} 

					// free 
					mbedtls_x509_crt_free(&chain);
					mbedtls_x509_crt_free(&root_ca);

					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] Certificate validation: success.");

				// free data structs
				mbedtls_x509_crt_free(&chain);
				mbedtls_x509_crt_free(&root_ca);

				return true;
			}
			else if (this->Type == Ed25519_Signing_Key) {
				//
				// TODO
				//
			}

			return false;
		}
	};
}