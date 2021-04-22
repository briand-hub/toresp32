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

/* LibSodium found for Ed25519 signatures! It's on framwork :-D */
#include <sodium.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand {

	/**
	 * Base class just to define common methods and fields to simplify code. Valid for some certificates.
	*/
	class BriandTorCertificateBase {
		protected:

		/**
		 * Method verifies the current X.509 certificate (if applicable) against a root CA X.509 certificate.
		 * All verifications (valid dates, valid signatures, etc.) <b>should</b> be done by the MbedTLS library.
		 * @param x509CaCertificate the root certificate (RSA1024 Identity)
		 * @param rsaMinKeySize minimum allowed rsa key size (mbedtls invalidates certificate if key size is less than 2048bits , April 2021)
		 * @return true if valid, false otherwise
		*/
		virtual bool X509ValidateAgainstCa(const unique_ptr<vector<unsigned char>>& x509CaCertificateContents, unsigned short rsaMinKeySize = 1024) {
			// Buffers needed
			unique_ptr<unsigned char[]> tempBuffer = nullptr;
			unsigned int caSize = x509CaCertificateContents->size() + 1; // +1 because MUST be null-terminated
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
			std::copy(x509CaCertificateContents->begin(), x509CaCertificateContents->end(), tempBuffer.get() );

			// Parse CA and add to chain
			if ( mbedtls_x509_crt_parse(&chain, reinterpret_cast<const unsigned char*>(tempBuffer.get()), caSize) != 0) {
				if (DEBUG) Serial.printf("[DEBUG] %s validation: failed to parse rootCA.", this->GetCertificateName().c_str());

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
				if (DEBUG) Serial.printf("[DEBUG] %s validation: failed to parse peer.", this->GetCertificateName().c_str());

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
					mbedtls_x509_crt_verify_info( reinterpret_cast<char*>(tempBuffer.get()), 256,"", verification_flags);
					Serial.printf("[DEBUG] %s validation: failed because %s\n", this->GetCertificateName().c_str(), reinterpret_cast<const char*>(tempBuffer.get()));
				} 

				// free 
				mbedtls_x509_crt_free(&chain);
				mbedtls_x509_crt_free(&root_ca);

				return false;
			}

			if (DEBUG) Serial.printf("[DEBUG] Type %s validation: success.\n", this->GetCertificateName().c_str());

			// free data structs
			mbedtls_x509_crt_free(&chain);
			mbedtls_x509_crt_free(&root_ca);

			return true;
		}

		public:

		/** Cert Type */
		unsigned char Type;
		/** Maximum allowed certType */
		static const unsigned char MAX_CERT_VALUE = 7;
		/** Content bytes of the certificate (raw, not including header) */
		unique_ptr<vector<unsigned char>> Contents;

		/** Constructor inits the Contents vector */
		BriandTorCertificateBase() {
			this->Type = 0;
			this->Contents = make_unique<vector<unsigned char>>();
		}
	
		/** Copy constructor to avoid error "use of deleted function..." */
		BriandTorCertificateBase(const BriandTorCertificateBase& other) {
			this->Contents = make_unique<vector<unsigned char>>();
			this->Contents->insert(this->Contents->begin(), other.Contents->begin(), other.Contents->end());
		}

		/** Destructor  */
		~BriandTorCertificateBase() {
			this->Contents.reset();
		}

		/** 
		 * Method return certificate name human-readable (for debug). MUST be implemented by derived classes. 
		 * @return Certificate name (string)
		*/
		virtual string GetCertificateName() = 0;

		/**
		 * Method return string containing certificate type and raw bytes 
		 * @return string with short info
		*/
		string GetCertificateShortInfo() {
			ostringstream builder;
			builder << "Certificate Type: " << static_cast<unsigned short>(this->Type) << "/" << this->GetCertificateName();
			builder << " Size: " << dec << this->Contents->size() << " bytes";
			builder << " Content bytes: ";

			for (unsigned int i = 0; i<this->Contents->size(); i++)
				builder << hex << std::setfill('0') << std::setw(2) << std::uppercase << static_cast<unsigned short>(this->Contents->at(i));

			return builder.str();
		}
	
		/**
		 * Print to serial certificate informations (debug) 
		*/
		virtual void PrintCertInfo() {
			if (DEBUG) {
				Serial.printf("[DEBUG] %s\n", this->GetCertificateShortInfo().c_str());
			}
		}
	};

	/**
	 * This is a support class, just keeps information about an Ed25519 certificate extension. 
	*/
	class BriandTorEd25519CertificateExtension {
		public:
		unsigned short ExtLength; 	// [2 bytes]
        unsigned char ExtType;   	// [1 byte]
        unsigned char ExtFlags;		// [1 byte]
        unique_ptr<vector<unsigned char>> ExtData; // [ExtLength bytes]
		bool valid;	// built correctly

		/**
		 * Build extension starting from raw bytes. Please check valid attribute! 
		*/
		BriandTorEd25519CertificateExtension(const unique_ptr<vector<unsigned char>>& rawdata) {
			this->valid = false;
			this->ExtLength = 0x0000;
			this->ExtType = 0x00;
			this->ExtFlags = 0x00;
			this->ExtData = make_unique<vector<unsigned char>>();
			
			if (DEBUG) {
				Serial.print("[DEBUG] Ed25519CertificateExtension raw bytes: ");
				BriandUtils::PrintByteBuffer(*rawdata.get(), rawdata->size()+1, rawdata->size()+1);
			}

			if (rawdata->size() < 4) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519CertificateExtension has poor bytes.");
				return;
			}

			this->ExtLength += static_cast<unsigned char>(rawdata->at(0) << 8);
			this->ExtLength += rawdata->at(1);
			this->ExtType = rawdata->at(2);
			this->ExtFlags = rawdata->at(3);

			if (DEBUG) Serial.printf("[DEBUG] Ed25519CertificateExtension length is of %d bytes.\n", this->ExtLength);

			if ( (rawdata->size() - 4) < this->ExtLength ) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519CertificateExtension has poor bytes for content.");
				return;
			}

			this->ExtData->insert(this->ExtData->begin(), rawdata->begin() + 4, rawdata->begin() + 4 + this->ExtLength);
			
			if (DEBUG) {
				Serial.printf("[DEBUG] Ed25519CertificateExtension ExtData: ");
				BriandUtils::PrintByteBuffer(*this->ExtData.get(), this->ExtLength + 1, this->ExtLength + 1);
			} 

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
			this->ExtData = make_unique<vector<unsigned char>>();
			this->ExtData->insert(this->ExtData->begin(), other.ExtData->begin(), other.ExtData->end());
		}

		~BriandTorEd25519CertificateExtension() {
			if (this->ExtData != nullptr) this->ExtData.reset();
		}

		/**
		 * Method returns extension total size in bytes
		 * @return Extension size in bytes (header + data)
		*/
		unsigned int TotalSize() {
			return 4 + this->ExtLength;
		}
	};

	/**
	 * Base class just to define common methods and fields to simplify code. Valid for Ed25519 Tor certificates.
	 * See https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
	*/
	class BriandTorEd25519CertificateBase {
		protected:
		const unsigned short certified_key_len = 32;
		const unsigned short signature_len = 64;
		bool isStructValid;

		public:
		/** Cert Type */
		unsigned char Type;
		unsigned char VERSION; // [1 Byte]
        unsigned char CERT_TYPE; // [1 Byte]
        unsigned int EXPIRATION_DATE; // [4 Bytes] HOURS since Unix epoch
        unsigned char CERT_KEY_TYPE;   // [1 byte]
        unique_ptr<unsigned char[]> CERTIFIED_KEY; // [32 Bytes] see certified_key_len
        unsigned char N_EXTENSIONS;    // [1 byte]
        unique_ptr<vector<BriandTorEd25519CertificateExtension>> EXTENSIONS; // [N_EXTENSIONS times]
        unique_ptr<unsigned char[]> SIGNATURE;       // [64 Bytes] see signature_len

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
		 * Constructor builds the certificate starting from the raw bytes. MUST call isStructValid() after
		 * @param raw_bytes Raw bytes (will not be touched or modified!) 
		*/
		BriandTorEd25519CertificateBase(const unique_ptr<vector<unsigned char>>& raw_bytes) {
			this->Type = 0;
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

			if (DEBUG) {
				Serial.printf("[DEBUG] Ed25519Certificate raw bytes: ");
				BriandUtils::PrintByteBuffer(*raw_bytes.get(), raw_bytes->size() + 1, raw_bytes->size() +1);
			} 

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

			// The last 64 bytes are signature, do not check, certificate validation will do.
			
			std::copy(raw_bytes->end() - this->signature_len, raw_bytes->end(), this->SIGNATURE.get());

			if (DEBUG) Serial.println("[DEBUG] Ed25519Certificate structure validated.");

			this->isStructValid = true; 
		}

		~BriandTorEd25519CertificateBase() {
			this->CERTIFIED_KEY.reset();
			this->SIGNATURE.reset();
			this->EXTENSIONS.reset();
		}

		/**
		 * Method to check if certificate has been correctly built from raw bytes 
		 * @return true if valid, false otherwise
		*/
		virtual bool IsStructureValid() {
			return this->isStructValid;
		}
	
		/**
		 * Method determines if certificate is expired (passed EXPIRATION_DATE (in hours!) since Unix epoch 
		 * @return true if expired , false if not
		*/
		virtual bool IsExpired() {
			return (this->EXPIRATION_DATE*3600 <= BriandUtils::GetUnixTime());
		}

		/** 
		 * Method return certificate name human-readable (for debug). MUST be implemented by derived classes. 
		 * @return Certificate name (string)
		*/
		virtual string GetCertificateName() = 0;

		/**
		 * Print to serial certificate informations (debug) 
		*/
		virtual void PrintCertInfo() {
			if (DEBUG) {		
				Serial.printf("[DEBUG] Certificate Type: %d/%s->EXPIRATION_DATE (Unix time HOURS) = %u\n", this->Type, this->GetCertificateName().c_str(), this->EXPIRATION_DATE);
				Serial.printf("[DEBUG] Certificate Type: %d/%s->EXPIRATION_DATE valid = %d\n", this->Type, this->GetCertificateName().c_str(), !this->IsExpired() );
				Serial.printf("[DEBUG] Certificate Type: %d/%s->CERTIFIED_KEY = ", this->Type, this->GetCertificateName().c_str());
				BriandUtils::PrintOldStyleByteBuffer(this->CERTIFIED_KEY.get(), this->certified_key_len, this->certified_key_len+1, this->certified_key_len);
				
				if (this->EXTENSIONS->size() > 0) {
					for (int i = 0; i<this->N_EXTENSIONS; i++) {
						Serial.printf("[DEBUG] Certificate Type: %d/%s Extension %d of %d : ->type = 0x%02X ->flags = 0x%02X ->len = %hu bytes ->data = ", this->Type, this->GetCertificateName().c_str(), (i+1), this->N_EXTENSIONS, this->EXTENSIONS->at(i).ExtType, this->EXTENSIONS->at(i).ExtFlags, this->EXTENSIONS->at(i).ExtLength);
						BriandUtils::PrintByteBuffer(*this->EXTENSIONS->at(i).ExtData.get(), this->EXTENSIONS->at(i).ExtLength+1, this->EXTENSIONS->at(i).ExtLength+1);
					}
				}
				else {
					Serial.printf("[DEBUG] Certificate Type: %d/%s has no extensions.\n", this->Type, this->GetCertificateName().c_str());	
				}

				Serial.printf("[DEBUG] Certificate Type: %d/%s->SIGNATURE = ", this->Type, this->GetCertificateName().c_str());
				BriandUtils::PrintOldStyleByteBuffer(this->SIGNATURE.get(), this->signature_len, this->signature_len+1, this->signature_len);
			}
		}
	};

	/** CertType 2: RSA1024 Identity certificate, self-signed. DER encoded X509 */
	class BriandTorCertificate_RSA1024Identity : public BriandTorCertificateBase {
		public: 

		virtual string GetCertificateName() { return "RSA1024Identity certificate"; }
		
		/**
		 * Method verify X.509 certificate (valid dates, signatures and chain) against itself
		 * @param signAuthenticator CA root certificate
		 * @return true if all valid, false otherwise 
		*/
		virtual bool IsValid() {
			// Just call the base method because this certificate is a DER-encoded X.509 
			// The CA is .... myself
			return this->X509ValidateAgainstCa(this->Contents);
		}

		/**
		 * Method returns the RSA key length (in bits) of this certificate
		 * @return RSA key length in bits, 0 if error.
		*/
		virtual unsigned short GetRsaKeyLength() {
			// Buffers needed
			unsigned int certSize = this->Contents->size() + 1; // +1 because MUST be null-terminated
			auto tempBuffer = BriandUtils::GetOneOldBuffer( certSize ); // MUST be zero-init

			// Data structures needed
			mbedtls_x509_crt certificate;

			// Initialize data structures
			mbedtls_x509_crt_init(&certificate);

			// Copy contents
			std::copy(this->Contents->begin(), this->Contents->end(), tempBuffer.get() );

			// Parse certificate
			if ( mbedtls_x509_crt_parse(&certificate, reinterpret_cast<const unsigned char*>(tempBuffer.get()), certSize) != 0) {
				if (DEBUG) Serial.println("[DEBUG] RSA1024Identity certificate validation: failed to parse certificate.");

				// free
				mbedtls_x509_crt_free(&certificate);

				return 0;
			}

			unsigned int ks = mbedtls_rsa_get_len( mbedtls_pk_rsa(certificate.pk) ) * 8;

			// Free
			mbedtls_x509_crt_free(&certificate);

			return ks;
		}
	};

	/** CertType 1: Link key certificate certified by RSA1024 identity. DER encoded X509 */
	class BriandTorCertificate_LinkKey : public BriandTorCertificateBase {
		public:
		
		virtual string GetCertificateName() { return "LinkKey certificate"; }

		/**
		 * Method verify X.509 certificate (valid dates, signatures and chain) against the CA provided
		 * @param signAuthenticator CA root certificate
		 * @return true if all valid, false otherwise 
		*/
		virtual bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
			// Just call the base method because this certificate is a DER-encoded X.509 
			// The CA is the Cert type 2.
			return this->X509ValidateAgainstCa(signAuthenticator.Contents);
		}
	};

	/** CertType 3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key. DER encoded X509 */
	class BriandTorCertificate_RSA1024AuthenticateCellLink : public BriandTorCertificateBase {
		public: 

		virtual string GetCertificateName() { return "RSA1024AuthenticateCellLink certificate"; }
		
		/**
		 * Method verify X.509 certificate (valid dates, signatures and chain) against the CA provided
		 * @param signAuthenticator CA root certificate
		 * @return true if all valid, false otherwise 
		*/
		virtual bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
			// Just call the base method because this certificate is a DER-encoded X.509 
			// The CA is the Cert type 2.
			return this->X509ValidateAgainstCa(signAuthenticator.Contents);
		}
	};

	/** CertType 4: Ed25519 signing key, signed with RSA1024 Identity key. Tor-specific format. */
	class BriandTorCertificate_Ed25519SigningKey : public BriandTorEd25519CertificateBase {
		public:

		BriandTorCertificate_Ed25519SigningKey(const unique_ptr<vector<unsigned char>>& raw_bytes) : BriandTorEd25519CertificateBase(raw_bytes) {}

		virtual string GetCertificateName() { return "Ed25519SigningKey certificate"; }

		virtual bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
			if (this->IsExpired()) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519SigningKey is expired.");
				return false;
			}
				

			//
			// TODO
			//

			if (DEBUG) Serial.println("[DEBUG] Ed25519SigningKey is valid.");

			return true;
		}
	};

	/** CertType 5: TLS link certificate, signed with ed25519 signing key. Tor-specific format. */
	class BriandTorCertificate_TLSLink : public BriandTorEd25519CertificateBase {
		public:

		BriandTorCertificate_TLSLink(const unique_ptr<vector<unsigned char>>& raw_bytes) : BriandTorEd25519CertificateBase(raw_bytes) {}

		virtual string GetCertificateName() { return "TLSLink certificate"; }

		virtual bool IsValid(const BriandTorCertificate_Ed25519SigningKey& signAuthenticator) {
			if (this->IsExpired()) {
				if (DEBUG) Serial.println("[DEBUG] TLSLink is expired.");
				return false;
			}
				

			//
			// TODO
			//

			if (DEBUG) Serial.println("[DEBUG] TLSLink is valid.");

			return true;
		}
	};

	/** CertType 6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key. Tor-specific format. */
	class BriandTorCertificate_Ed25519AuthenticateCellLink : public BriandTorEd25519CertificateBase {
		public:

		BriandTorCertificate_Ed25519AuthenticateCellLink(const unique_ptr<vector<unsigned char>>& raw_bytes) : BriandTorEd25519CertificateBase(raw_bytes) {}

		virtual string GetCertificateName() { return "Ed25519AuthenticateCellLink certificate"; }

		virtual bool IsValid(const BriandTorCertificate_Ed25519SigningKey& signAuthenticator) {
			if (this->IsExpired()) {
				if (DEBUG) Serial.println("[DEBUG] Ed25519SigningKey is expired.");
				return false;
			}
				

			//
			// TODO
			//

			if (DEBUG) Serial.println("[DEBUG] Ed25519SigningKey is valid.");

			return true;
		}
	};

	/**
	 * CertType 7: Ed25519 identity, signed with RSA identity. Tor-specific format. 
	 * This class is useful to handle Tor specific RSA->Ed25519 Cross Certificate. 
	 * See https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
	*/
	class BriandTorCertificate_RSAEd25519CrossCertificate {
		private:
		const unsigned int ed25519_key_size = 32;
		bool isStructValid;

		protected:

		public:
		/** Cert Type */
		unsigned char Type;
		unique_ptr<unsigned char[]> ED25519_KEY; // [32 bytes]
       	unsigned int EXPIRATION_DATE; // [4 bytes] HOURS since Unix epoch
       	unsigned char SIGLEN; // [1 byte]
        unique_ptr<unsigned char[]> SIGNATURE; // [SIGLEN bytes]

		/**
		 * Constructor builds the certificate starting from the raw bytes. MUST call isStructValid() after
		 * @param raw_bytes Raw bytes (will not be touched or modified!) 
		*/
		BriandTorCertificate_RSAEd25519CrossCertificate(const unique_ptr<vector<unsigned char>>& raw_bytes) {
			this->Type = 0;
			this->isStructValid = false;
			this->ED25519_KEY = make_unique<unsigned char[]>(ed25519_key_size);
			this->EXPIRATION_DATE = 0x00000000;
			this->SIGNATURE = nullptr; 
			this->SIGLEN = 0x00;

			if (DEBUG) {
				Serial.printf("[DEBUG] RSAEd25519CrossCertificate raw bytes: ");
				BriandUtils::PrintByteBuffer(*raw_bytes.get(), raw_bytes->size()+1, raw_bytes->size()+1);
			}

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

		~BriandTorCertificate_RSAEd25519CrossCertificate() {
			this->ED25519_KEY.reset();
			if (this->SIGNATURE != nullptr) this->SIGNATURE.reset();
		}

		/**
		 * Method to check if certificate has been correctly built from raw bytes 
		 * @return true if valid, false otherwise
		*/
		bool IsStructureValid() {
			return this->isStructValid;
		}
	
		/**
		 * Method determines if certificate is expired (passed EXPIRATION_DATE (in hours!) since Unix epoch 
		 * @return true if expired , false if not
		*/
		bool IsExpired() {
			return (this->EXPIRATION_DATE*3600 <= BriandUtils::GetUnixTime());
		}

		/**
		 * Method validates the certificate (check signature validated by RSA 1024 Identity key) 
		*/
		bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
			if (this->IsExpired()) {
				if (DEBUG) Serial.println("[DEBUG] RSAEd25519CrossCertificate is expired.");
				return false;
			}
				

			//
			// TODO
			//

			if (DEBUG) Serial.println("[DEBUG] RSAEd25519CrossCertificate is valid.");

			return true;
		}

		/**
		 * Print to serial certificate informations (debug) 
		*/
		void PrintCertInfo() {
			if (DEBUG) {				
				Serial.printf("[DEBUG] RSAEd25519CrossCertificate->ED25519_KEY = ");
				BriandUtils::PrintOldStyleByteBuffer(this->ED25519_KEY.get(), this->ed25519_key_size, this->ed25519_key_size+1, this->ed25519_key_size);
				Serial.printf("[DEBUG] RSAEd25519CrossCertificate->EXPIRATION_DATE (Unix time HOURS) = %u\n", this->EXPIRATION_DATE);
				//Serial.printf("[DEBUG] RSAEd25519CrossCertificate->EXPIRATION_DATE valid = %d\n", !this->isExpired() );
				Serial.printf("[DEBUG] RSAEd25519CrossCertificate->SIGNATURE = ");
				BriandUtils::PrintOldStyleByteBuffer(this->SIGNATURE.get(), this->SIGLEN, this->SIGLEN+1, this->SIGLEN);
			}
		}
	};
}