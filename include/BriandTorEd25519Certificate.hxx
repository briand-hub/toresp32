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
#include <vector>

/* LibSodium found for Ed25519 signatures! It's on framwork :-D */
#include <sodium.h>

#include "BriandUtils.hxx"

using namespace std;

namespace Briand {
	/* List of ED25519 certificate types (CERT_TYPE field). HAS NOTHING TO DO WITH CERTS CELL!!!! */
	enum BriandTorEd25519CerType : unsigned char {
   		/* [00],[01],[02],[03] - Reserved to avoid conflict with types used in CERTS cells.*/
		/* [07] - Reserved for RSA identity cross-certification; (see section 2.3 above, and tor-spec.txt section 4.2)*/

		Ed25519_signing_key_with_an_identity_key = 4,
		TLS_link_certificate_signed_with_ed25519_signing_key = 5,
		Ed25519_authentication_key_signed_with_ed25519_signing_key = 6,
		
		OS_short_term_descriptor_signing_key = 8, // signed with blinded public key.
		OS_intro_point_auth_key_cross_certifies_descriptor_key = 9,
		ntor_onion_key_corss_certifies_ed25519_identity_key = 0xA,
		ntor_extra_encryption_key_corss_certifies_descriptor_key = 0xB
	};

	/**
	 * This is a support class, just keeps information about a certificate extension. 
	*/
	class BriandTorEd25519CertificateExtension {
		public:
		unsigned short ExtLength; 	// [2 bytes]
        unsigned char ExtType;   	// [1 byte]
        unsigned char ExtFlags;		// [1 byte]
        unique_ptr<unsigned char[]> ExtData; // [ExtLength bytes]
		bool valid;	// built correctly

		/**
		 * Build extension starting from raw bytes. Please check valid attribute! 
		*/
		BriandTorEd25519CertificateExtension(const unique_ptr<vector<unsigned char>>& rawdata) {
			this->valid = false;
			this->ExtLength = 0x0000;
			this->ExtType = 0x00;
			this->ExtFlags = 0x00;
			this->ExtData = nullptr;
			
			if (rawdata->size() < 4) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519CertificateExtension has poor bytes.");
				return;
			}

			this->ExtLength += rawdata->at(0) << 8;
			this->ExtLength += rawdata->at(1);
			this->ExtType = rawdata->at(2);
			this->ExtFlags = rawdata->at(3);

			if ( (rawdata->size() - 4) < this->ExtLength ) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519CertificateExtension has poor bytes for content.");
				return;
			}

			this->ExtData = make_unique<unsigned char[]>( this->ExtLength );
			std::copy(rawdata->begin() + 4, rawdata->begin() + 4 + this->ExtLength, this->ExtData.get());

			if (DEBUG) Serial.println("[DEBUG] Ed25519CertificateExtension structure is valid.");

			this->valid = true;
		}

		/**
		 * Copy-constructor to avoid error: use of deleted function with make_unique
		*/
		BriandTorEd25519CertificateExtension(const BriandTorEd25519CertificateExtension& other) {
			this->ExtType = other.ExtType;
			this->ExtType = other.ExtType;
			this->ExtFlags = other.ExtFlags;
			this->valid = other.valid;
			this->ExtData = make_unique<unsigned char[]>(other.ExtLength);
			std::copy(other.ExtData.get(), other.ExtData.get() + other.ExtLength, this->ExtData.get());
		}

		~BriandTorEd25519CertificateExtension() {
			if (this->ExtData != nullptr) this->ExtData.reset();
		}

		unsigned int TotalSize() {
			return 4 + this->ExtLength;
		}
	};

	/**
	 * This class is useful to handle Tor specific Ed25519 Certificate. 
	 * See https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
	*/
	class BriandTorEd25519Certificate {
		private:
		const unsigned short certified_key_len = 32;
		const unsigned short signature_len = 64;
		bool isStructValid;

		public:
		unsigned char VERSION; // [1 Byte]
        unsigned char CERT_TYPE; // [1 Byte]
        unsigned int EXPIRATION_DATE; // [4 Bytes]
        unsigned char CERT_KEY_TYPE;   // [1 byte]
        unique_ptr<unsigned char[]> CERTIFIED_KEY; // [32 Bytes] see certified_key_len
        unsigned char N_EXTENSIONS;    // [1 byte]
        unique_ptr<vector<BriandTorEd25519CertificateExtension>> EXTENSIONS; // [N_EXTENSIONS times]
        unique_ptr<unsigned char[]> SIGNATURE;       // [64 Bytes] see signature_len

		/**
		 * Constructor builds the certificate starting from the raw bytes. MUST call isStructValid() after
		 * @param raw_bytes Raw bytes (will not be touched or modified!) 
		*/
		BriandTorEd25519Certificate(const unique_ptr<vector<unsigned char>>& raw_bytes) {
			this->isStructValid = false;
			this->VERSION = 0x00;
			this->CERT_TYPE = 0x00;
			this->EXPIRATION_DATE = 0x00000000;
			this->CERT_KEY_TYPE = 0x00;
			this->N_EXTENSIONS = 0x00;
			this->CERTIFIED_KEY = make_unique<unsigned char[]>( this->certified_key_len );
			this->SIGNATURE = make_unique<unsigned char[]>( this->signature_len );
			this->EXTENSIONS = make_unique<vector<BriandTorEd25519CertificateExtension>>();

			// start to build

			if (raw_bytes->size() < 40) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519Certificate has too poor bytes.");
				return;
			}

			this->VERSION += raw_bytes->at(0);
			this->CERT_TYPE += raw_bytes->at(1);
			this->EXPIRATION_DATE += raw_bytes->at(2) << 24;
			this->EXPIRATION_DATE += raw_bytes->at(3) << 16;
			this->EXPIRATION_DATE += raw_bytes->at(4) << 8;
			this->EXPIRATION_DATE += raw_bytes->at(5);
			this->CERT_KEY_TYPE += raw_bytes->at(6);

			// First validity checks

			// The "VERSION" field holds the value [01]
			// However I just check > 0 for future versions
			if (this->VERSION < 0x01) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519Certificate has invalid VERSION.");
				return;
			}

			// The "CERT_TYPE" field holds a value depending on the type of certificate. (See appendix A.1.)
			// no check there...

			// The CERTIFIED_KEY field is an Ed25519 public key if CERT_KEY_TYPE is [01], or a digest of some other key type
   			// depending on the value of CERT_KEY_TYPE
			
			// no check there...

			// copy data
			std::copy(raw_bytes->begin() + 7, raw_bytes->begin() + 7 + certified_key_len, this->CERTIFIED_KEY.get());

			this->N_EXTENSIONS = raw_bytes->at(7 + certified_key_len);

			if (this->N_EXTENSIONS > 0x00) {
				// There are extensions, each can have a variable size.
				// In order to do a right work, prepare a copy of the buffer 
				// and erase for the first Extension->TotalSize() bytes to do the next one.

				if (DEBUG) Serial.printf("[DEBUG] Ed25519Certificate has %d extensions, checking.\n", this->N_EXTENSIONS);

				unsigned int extensionsStartAt = 7 + certified_key_len + 1;
				unsigned char remainingExtensions = this->N_EXTENSIONS;
				auto extBuffer = make_unique<vector<unsigned char>>();
				extBuffer->insert(extBuffer->begin(), raw_bytes->begin() + extensionsStartAt, raw_bytes->end());

				while (remainingExtensions > 0) {
					BriandTorEd25519CertificateExtension ext { extBuffer };
					if (!ext.valid) {
						if (DEBUG) Serial.printf("[DEBUG] Ed25519Certificate extension %d of %d is invalid.\n", (this->N_EXTENSIONS - remainingExtensions) + 1, this->N_EXTENSIONS);
						return;
					}

					this->EXTENSIONS->push_back(ext);
					remainingExtensions--;
					extBuffer->erase(extBuffer->begin(), extBuffer->begin() + ext.TotalSize());
				}

				extBuffer.reset();
			}

			// The last 64 bytes are this, do not check, certificate validation will do.
			
			std::copy(raw_bytes->end() - this->signature_len, raw_bytes->end(), this->SIGNATURE.get());

			if (DEBUG) Serial.println("[DEBUG] Ed25519Certificate structure validated.");

			this->isStructValid = true; 
		}

		~BriandTorEd25519Certificate() {
			this->CERTIFIED_KEY.reset();
			this->SIGNATURE.reset();
			this->EXTENSIONS.reset();
		}

		/**
		 * Method to check if certificate has been correctly built from raw bytes 
		 * @return true if valid, false otherwise
		*/
		bool isStructureValid() {
			return this->isStructValid;
		}
	};

	/**
	 * This class is useful to handle Tor specific RSA->Ed25519 Cross Certificate. 
	 * See https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
	*/
	class BriandTorRSAEd25519CrossCertificate {
		private:
		const unsigned int ed25519_key_size = 32;
		bool isStructValid;

		protected:
		public:
		unique_ptr<unsigned char[]> ED25519_KEY; // [32 bytes]
       	unsigned int EXPIRATION_DATE; // [4 bytes]
       	unsigned char SIGLEN; // [1 byte]
        unique_ptr<unsigned char[]> SIGNATURE; // [SIGLEN bytes]

		/**
		 * Constructor builds the certificate starting from the raw bytes. MUST call isStructValid() after
		 * @param raw_bytes Raw bytes (will not be touched or modified!) 
		*/
		BriandTorRSAEd25519CrossCertificate(const unique_ptr<vector<unsigned char>>& raw_bytes) {
			this->isStructValid = false;
			this->ED25519_KEY = make_unique<unsigned char[]>(ed25519_key_size);
			this->EXPIRATION_DATE = 0x00000000;
			this->SIGNATURE = nullptr; 
			this->SIGLEN = 0x00;

			// start to build

			if (raw_bytes->size() < 37) {
				if (DEBUG) Serial.println("[DEBUG] RSAEd25519CrossCertificate has too poor bytes.");
				return;
			} 
			
			// copy data
			std::copy(raw_bytes->begin(), raw_bytes->begin() + this->ed25519_key_size, this->ED25519_KEY.get());
			
			this->EXPIRATION_DATE += raw_bytes->at(32) << 24;
			this->EXPIRATION_DATE += raw_bytes->at(33) << 16;
			this->EXPIRATION_DATE += raw_bytes->at(34) << 8;
			this->EXPIRATION_DATE += raw_bytes->at(35);
			this->SIGLEN += raw_bytes->at(36);

			if (raw_bytes->size() < (36 + this->SIGLEN)) {
				if (DEBUG) Serial.println("[DEBUG] RSAEd25519CrossCertificate has too poor bytes for signature.");
				return;
			} 
			if (this->SIGLEN < 1) {
				if (DEBUG) Serial.println("[DEBUG] RSAEd25519CrossCertificate has an invalid SIGLEN value.");
				return;
			}

			this->SIGNATURE = make_unique<unsigned char[]>( this->SIGLEN );

			// copy data
			std::copy(raw_bytes->begin()+36, raw_bytes->begin()+36+this->SIGLEN, this->SIGNATURE.get());

			if (DEBUG) Serial.println("[DEBUG] RSAEd25519CrossCertificate structure validated.");

			this->isStructValid = true; 
		}

		~BriandTorRSAEd25519CrossCertificate() {
			this->ED25519_KEY.reset();
			if (this->SIGNATURE != nullptr) this->SIGNATURE.reset();
		}

		/**
		 * Method to check if certificate has been correctly built from raw bytes 
		 * @return true if valid, false otherwise
		*/
		bool isStructureValid() {
			return this->isStructValid;
		}
	};
}