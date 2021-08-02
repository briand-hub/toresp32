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

#include "BriandTorCertificates.hxx"
#include "BriandDefines.hxx"
#include "BriandTorCryptoUtils.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand {

	// class BriandTorCertificateBase {

	BriandTorCertificateBase::BriandTorCertificateBase() {
		this->Type = 0;
		this->Contents = make_unique<vector<unsigned char>>();
	}

	BriandTorCertificateBase::BriandTorCertificateBase(const BriandTorCertificateBase& other) {
		this->Contents = make_unique<vector<unsigned char>>();
		this->Contents->insert(this->Contents->begin(), other.Contents->begin(), other.Contents->end());
	}

	BriandTorCertificateBase::~BriandTorCertificateBase() {
		this->Contents.reset();
	}

	string BriandTorCertificateBase::GetCertificateShortInfo() {
		ostringstream builder;
		builder << "Certificate Type: " << static_cast<unsigned short>(this->Type) << "/" << this->GetCertificateName();
		builder << " Size: " << dec << this->Contents->size() << " bytes";
		builder << " Content bytes: ";

		for (unsigned int i = 0; i<this->Contents->size(); i++)
			builder << hex << std::setfill('0') << std::setw(2) << std::uppercase << static_cast<unsigned short>(this->Contents->at(i));

		return builder.str();
	}

	void BriandTorCertificateBase::PrintCertInfo() {
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] %s\n", this->GetCertificateShortInfo().c_str());
		}
	}


	// class BriandTorEd25519CertificateExtension {
		
	BriandTorEd25519CertificateExtension::BriandTorEd25519CertificateExtension(const unique_ptr<vector<unsigned char>>& rawdata) {
		this->valid = false;
		this->ExtLength = 0x0000;
		this->ExtType = 0x00;
		this->ExtFlags = 0x00;
		this->ExtData = make_unique<vector<unsigned char>>();
		
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Ed25519CertificateExtension raw bytes: ");
			BriandUtils::PrintByteBuffer(*rawdata.get(), rawdata->size()+1, rawdata->size()+1);
		}

		if (rawdata->size() < 4) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519CertificateExtension has poor bytes.\n");
			return;
		}

		this->ExtLength += static_cast<unsigned char>(rawdata->at(0) << 8);
		this->ExtLength += rawdata->at(1);
		this->ExtType = rawdata->at(2);
		this->ExtFlags = rawdata->at(3);

		ESP_LOGD(LOGTAG, "[DEBUG] Ed25519CertificateExtension length is of %d bytes.\n", this->ExtLength);

		if ( (rawdata->size() - 4) < this->ExtLength ) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519CertificateExtension has poor bytes for content.\n");
			return;
		}

		this->ExtData->insert(this->ExtData->begin(), rawdata->begin() + 4, rawdata->begin() + 4 + this->ExtLength);
		
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Ed25519CertificateExtension ExtData: ");
			BriandUtils::PrintByteBuffer(*this->ExtData.get(), this->ExtLength + 1, this->ExtLength + 1);
		} 

		ESP_LOGD(LOGTAG, "[DEBUG] Ed25519CertificateExtension structure is valid.\n");

		this->valid = true;
	}

	BriandTorEd25519CertificateExtension::BriandTorEd25519CertificateExtension(const BriandTorEd25519CertificateExtension& other) {
		this->ExtType = other.ExtType;
		this->ExtType = other.ExtType;
		this->ExtFlags = other.ExtFlags;
		this->valid = other.valid;
		this->ExtData = make_unique<vector<unsigned char>>();
		this->ExtData->insert(this->ExtData->begin(), other.ExtData->begin(), other.ExtData->end());
	}

	BriandTorEd25519CertificateExtension::~BriandTorEd25519CertificateExtension() {
		if (this->ExtData != nullptr) this->ExtData.reset();
	}

	unsigned int BriandTorEd25519CertificateExtension::TotalSize() {
		return 4 + this->ExtLength;
	}


	//class BriandTorEd25519CertificateBase {

	BriandTorEd25519CertificateBase::BriandTorEd25519CertificateBase(const unique_ptr<vector<unsigned char>>& raw_bytes) {
		this->Type = 0;
		this->isStructValid = false;
		this->VERSION = 0x00;
		this->CERT_TYPE = 0x00;
		this->EXPIRATION_DATE = 0x00000000;
		this->CERT_KEY_TYPE = 0x00;
		this->N_EXTENSIONS = 0x00;
		this->CERTIFIED_KEY = make_unique<vector<unsigned char>>();
		this->SIGNATURE = make_unique<vector<unsigned char>>();
		this->EXTENSIONS = make_unique<vector<BriandTorEd25519CertificateExtension>>();
		this->non_signature_parts = make_unique<vector<unsigned char>>();

		// start to build

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Ed25519Certificate raw bytes: ");
			BriandUtils::PrintByteBuffer(*raw_bytes.get(), raw_bytes->size() + 1, raw_bytes->size() +1);
		} 

		if (raw_bytes->size() < 40) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519Certificate has too poor bytes.\n");
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
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519Certificate has invalid VERSION.\n");
			return;
		}

		// The "CERT_TYPE" field holds a value depending on the type of certificate. (See appendix A.1.)
		// no check there...

		// The CERTIFIED_KEY field is an Ed25519 public key if CERT_KEY_TYPE is [01], or a digest of some other key type
		// depending on the value of CERT_KEY_TYPE
		
		// no check there...

		// copy data
		//std::copy(raw_bytes->begin() + 7, raw_bytes->begin() + 7 + certified_key_len, this->CERTIFIED_KEY.get());
		this->CERTIFIED_KEY->insert(this->CERTIFIED_KEY->begin(), raw_bytes->begin() + 7, raw_bytes->begin() + 7 + certified_key_len);

		this->N_EXTENSIONS = raw_bytes->at(7 + certified_key_len);

		if (this->N_EXTENSIONS > 0x00) {
			// There are extensions, each can have a variable size.
			// In order to do a right work, prepare a copy of the buffer 
			// and erase for the first Extension->TotalSize() bytes to do the next one.

			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519Certificate has %d extensions, checking.\n", this->N_EXTENSIONS);

			unsigned int extensionsStartAt = 7 + certified_key_len + 1;
			unsigned char remainingExtensions = this->N_EXTENSIONS;
			auto extBuffer = make_unique<vector<unsigned char>>();
			extBuffer->insert(extBuffer->begin(), raw_bytes->begin() + extensionsStartAt, raw_bytes->end());

			while (remainingExtensions > 0) {
				BriandTorEd25519CertificateExtension ext { extBuffer };
				if (!ext.valid) {
					ESP_LOGD(LOGTAG, "[DEBUG] Ed25519Certificate extension %d of %d is invalid.\n", (this->N_EXTENSIONS - remainingExtensions) + 1, this->N_EXTENSIONS);
					return;
				}

				this->EXTENSIONS->push_back(ext);
				remainingExtensions--;
				extBuffer->erase(extBuffer->begin(), extBuffer->begin() + ext.TotalSize());
			}

			extBuffer.reset();
		}

		// The last 64 bytes are signature, do not check, certificate validation will do.
		this->SIGNATURE->insert(this->SIGNATURE->begin(), raw_bytes->end() - this->signature_len, raw_bytes->end());
		//std::copy(raw_bytes->end() - this->signature_len, raw_bytes->end(), this->SIGNATURE.get());

		// The signature is formed by signing the first N-64 bytes of the certificate.
		// maybe N-64 stand for "all before the signature" ? yes that is...

		// So... all bytes before are the non signature parts, used for certificate signature
		this->non_signature_parts->insert(this->non_signature_parts->begin(), raw_bytes->begin(), raw_bytes->end() - signature_len);

		ESP_LOGD(LOGTAG, "[DEBUG] Ed25519Certificate structure validated.\n");

		this->isStructValid = true; 
	}

	BriandTorEd25519CertificateBase::~BriandTorEd25519CertificateBase() {
		this->CERTIFIED_KEY.reset();
		this->SIGNATURE.reset();
		this->EXTENSIONS.reset();
		this->non_signature_parts.reset();
	}

	bool BriandTorEd25519CertificateBase::IsStructureValid() {
		return this->isStructValid;
	}

	bool BriandTorEd25519CertificateBase::IsExpired() {
		return (this->EXPIRATION_DATE*3600 <= BriandUtils::GetUnixTime());
	}

	bool BriandTorEd25519CertificateBase::IsSignatureIsValid(const unique_ptr<vector<unsigned char>>& ed25519PK) {
		// For ed certificates all signatures are made with an ed key from other certificates
		// (listed somewhere else, thus parameter) and must not be expired

		ESP_LOGD(LOGTAG, "[DEBUG] %s signature verification.\n", this->GetCertificateName().c_str());

		bool signatureValid = BriandTorCryptoUtils::CheckSignature_Ed25519(this->non_signature_parts, ed25519PK, this->SIGNATURE);

		ESP_LOGD(LOGTAG, "[DEBUG] %s signature verification result: %d\n", this->GetCertificateName().c_str(), signatureValid);

		return signatureValid;
	}

	void BriandTorEd25519CertificateBase::PrintCertInfo() {
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {		
			printf("[DEBUG] Certificate Type: %d/%s->EXPIRATION_DATE (Unix time HOURS) = 0x %08X\n", this->Type, this->GetCertificateName().c_str(), this->EXPIRATION_DATE);
			printf("[DEBUG] Certificate Type: %d/%s->EXPIRATION_DATE valid = %d\n", this->Type, this->GetCertificateName().c_str(), !this->IsExpired() );
			printf("[DEBUG] Certificate Type: %d/%s->CERTIFIED_KEY = ", this->Type, this->GetCertificateName().c_str());
			//BriandUtils::PrintOldStyleByteBuffer(this->CERTIFIED_KEY.get(), this->certified_key_len, this->certified_key_len+1, this->certified_key_len);
			BriandUtils::PrintByteBuffer(*this->CERTIFIED_KEY.get(), this->CERTIFIED_KEY->size(), this->CERTIFIED_KEY->size());
			
			if (this->EXTENSIONS->size() > 0) {
				for (int i = 0; i<this->N_EXTENSIONS; i++) {
					printf("[DEBUG] Certificate Type: %d/%s Extension %d of %d : ->type = 0x%02X ->flags = 0x%02X ->len = %hu bytes ->data = ", this->Type, this->GetCertificateName().c_str(), (i+1), this->N_EXTENSIONS, this->EXTENSIONS->at(i).ExtType, this->EXTENSIONS->at(i).ExtFlags, this->EXTENSIONS->at(i).ExtLength);
					BriandUtils::PrintByteBuffer(*this->EXTENSIONS->at(i).ExtData.get(), this->EXTENSIONS->at(i).ExtLength+1, this->EXTENSIONS->at(i).ExtLength+1);
				}
			}
			else {
				printf("[DEBUG] Certificate Type: %d/%s has no extensions.\n", this->Type, this->GetCertificateName().c_str());	
			}

			printf("[DEBUG] Certificate Type: %d/%s->SIGNATURE = ", this->Type, this->GetCertificateName().c_str());
			//BriandUtils::PrintOldStyleByteBuffer(this->SIGNATURE.get(), this->signature_len, this->signature_len+1, this->signature_len);
			BriandUtils::PrintByteBuffer(*this->SIGNATURE.get(), this->SIGNATURE->size(), this->SIGNATURE->size());
		}
	}


	//class BriandTorCertificate_RSA1024Identity : public BriandTorCertificateBase {

	string BriandTorCertificate_RSA1024Identity::GetCertificateName() { return "RSA1024Identity certificate"; }
	
	bool BriandTorCertificate_RSA1024Identity::IsValid() {
		// This certificate is a DER-encoded X.509 
		// The CA is the Cert type 2 and is ... myself!

		ESP_LOGD(LOGTAG, "[DEBUG] %s - Starting validate.\n", this->GetCertificateName().c_str());
		bool validationResult = BriandTorCryptoUtils::X509Validate(this->Contents, this->Contents);
		ESP_LOGD(LOGTAG, "[DEBUG] %s - Validation end with result %d.\n", this->GetCertificateName().c_str(), validationResult);

		return validationResult;
	}

	unsigned short BriandTorCertificate_RSA1024Identity::GetRsaKeyLength() {
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
			ESP_LOGD(LOGTAG, "[DEBUG] RSA1024Identity certificate validation: failed to parse certificate.\n");

			// free
			mbedtls_x509_crt_free(&certificate);

			return 0;
		}

		unsigned int ks = mbedtls_rsa_get_len( mbedtls_pk_rsa(certificate.pk) ) * 8;

		// Free
		mbedtls_x509_crt_free(&certificate);

		return ks;
	}


	//class BriandTorCertificate_RSAEd25519CrossCertificate {

	BriandTorCertificate_RSAEd25519CrossCertificate::BriandTorCertificate_RSAEd25519CrossCertificate(const unique_ptr<vector<unsigned char>>& raw_bytes) {
		this->Type = 0;
		this->isStructValid = false;
		this->ED25519_KEY = make_unique<vector<unsigned char>>();
		this->EXPIRATION_DATE = 0x00000000;
		this->SIGNATURE = nullptr; 
		this->SIGLEN = 0x00;

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] RSAEd25519CrossCertificate raw bytes: ");
			BriandUtils::PrintByteBuffer(*raw_bytes.get(), raw_bytes->size()+1, raw_bytes->size()+1);
		}

		// start to build

		if (raw_bytes->size() < 37) {
			ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate has too poor bytes.\n");
			return;
		} 
		
		// copy data
		//std::copy(raw_bytes->begin(), raw_bytes->begin() + this->ed25519_key_size, this->ED25519_KEY.get());
		this->ED25519_KEY->insert(this->ED25519_KEY->begin(), raw_bytes->begin(), raw_bytes->begin() + this->ed25519_key_size);
		
		this->EXPIRATION_DATE += raw_bytes->at(32) << 24;
		this->EXPIRATION_DATE += raw_bytes->at(33) << 16;
		this->EXPIRATION_DATE += raw_bytes->at(34) << 8;
		this->EXPIRATION_DATE += raw_bytes->at(35);
		this->SIGLEN += raw_bytes->at(this->ed25519_key_size + 4);

		if (raw_bytes->size() < (this->ed25519_key_size + 4 + this->SIGLEN)) {
			ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate has too poor bytes for signature.\n");
			return;
		} 
		if (this->SIGLEN < 1) {
			ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate has an invalid SIGLEN value.\n");
			return;
		}

		this->SIGNATURE = make_unique<vector<unsigned char>>();

		// copy data from byte 37 for siglen bytes
		//std::copy(raw_bytes->begin()+37, raw_bytes->begin()+37+this->SIGLEN, this->SIGNATURE.get());
		this->SIGNATURE->insert(this->SIGNATURE->begin(), raw_bytes->begin()+this->ed25519_key_size+4+1, raw_bytes->begin()+37+this->SIGLEN);

		ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate structure validated.\n");

		this->isStructValid = true; 
	}

	BriandTorCertificate_RSAEd25519CrossCertificate::~BriandTorCertificate_RSAEd25519CrossCertificate() {
		this->ED25519_KEY.reset();
		if (this->SIGNATURE != nullptr) this->SIGNATURE.reset();
	}

	bool BriandTorCertificate_RSAEd25519CrossCertificate::IsStructureValid() {
		return this->isStructValid;
	}

	bool BriandTorCertificate_RSAEd25519CrossCertificate::IsExpired() {
		return (this->EXPIRATION_DATE*3600 <= BriandUtils::GetUnixTime());
	}

	bool BriandTorCertificate_RSAEd25519CrossCertificate::IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
		if (this->IsExpired()) {
			ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate is expired.\n");
			return false;
		}
			
		// Check signature
		ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate check if signed by RSA1024 Identity.\n");

		/*The signature is computed on the SHA256 hash of the non-signature parts of the certificate, prefixed with the	string "Tor TLS RSA/Ed25519 cross-certificate".*/

		// HINT: non-signature means all bytes but NOT SIGLEN and SIGNATURE. So only prepended string + EXPIRATIONDATE + EDKEY
		// in such way prepare buffer
		auto messageToVerify = BriandUtils::HexStringToVector("", "Tor TLS RSA/Ed25519 cross-certificate");
		//for (unsigned int i=0; i<ed25519_key_size; i++) messageToVerify->push_back( this->ED25519_KEY[i] );
		messageToVerify->insert(messageToVerify->begin() + messageToVerify->size(), this->ED25519_KEY->begin(), this->ED25519_KEY->end());
		messageToVerify->push_back( static_cast<unsigned char>( (this->EXPIRATION_DATE & 0xFF000000) >> 24 ));
		messageToVerify->push_back( static_cast<unsigned char>( (this->EXPIRATION_DATE & 0x00FF0000) >> 16 ));
		messageToVerify->push_back( static_cast<unsigned char>( (this->EXPIRATION_DATE & 0x0000FF00) >> 8 ));
		messageToVerify->push_back( static_cast<unsigned char>( (this->EXPIRATION_DATE & 0x000000FF) ));
		
		bool signedCorrectly = BriandTorCryptoUtils::CheckSignature_RSASHA256(messageToVerify, signAuthenticator.Contents, this->SIGNATURE);

		if (signedCorrectly) {
			ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate has valid signature.\n");
		}
		else { 
			ESP_LOGD(LOGTAG, "[DEBUG] RSAEd25519CrossCertificate has invalid signature!\n");
		}

		return signedCorrectly;
	}

	void BriandTorCertificate_RSAEd25519CrossCertificate::PrintCertInfo() {
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {				
			printf("[DEBUG] RSAEd25519CrossCertificate->ED25519_KEY = ");
			BriandUtils::PrintByteBuffer(*this->ED25519_KEY.get(), this->ed25519_key_size, this->ed25519_key_size);
			printf("[DEBUG] RSAEd25519CrossCertificate->EXPIRATION_DATE (Unix time HOURS) = 0x %08X\n", this->EXPIRATION_DATE);
			//printf("[DEBUG] RSAEd25519CrossCertificate->EXPIRATION_DATE valid = %d\n", !this->isExpired() );
			printf("[DEBUG] RSAEd25519CrossCertificate->SIGNATURE = ");
			BriandUtils::PrintByteBuffer(*this->SIGNATURE.get(), this->SIGLEN, this->SIGLEN);
		}
	}


	//class BriandTorCertificate_LinkKey : public BriandTorCertificateBase {

	string BriandTorCertificate_LinkKey::GetCertificateName() { return "LinkKey certificate"; }

	bool BriandTorCertificate_LinkKey::IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
		// This certificate is a DER-encoded X.509 
		// The CA is the Cert type 2.

		ESP_LOGD(LOGTAG, "[DEBUG] %s - Starting validate.\n", this->GetCertificateName().c_str());
		bool validationResult = BriandTorCryptoUtils::X509Validate(this->Contents, signAuthenticator.Contents);
		ESP_LOGD(LOGTAG, "[DEBUG] %s - Validation end with result %d.\n", this->GetCertificateName().c_str(), validationResult);

		return validationResult;
	}


	//class BriandTorCertificate_RSA1024AuthenticateCellLink : public BriandTorCertificateBase {

	string BriandTorCertificate_RSA1024AuthenticateCellLink::GetCertificateName() { return "RSA1024AuthenticateCellLink certificate"; }

	bool BriandTorCertificate_RSA1024AuthenticateCellLink::IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator) {
		// This certificate is a DER-encoded X.509 
		// The CA is the Cert type 2.

		ESP_LOGD(LOGTAG, "[DEBUG] %s - Starting validate.\n", this->GetCertificateName().c_str());
		bool validationResult = BriandTorCryptoUtils::X509Validate(this->Contents, signAuthenticator.Contents);
		ESP_LOGD(LOGTAG, "[DEBUG] %s - Validation end with result %d.\n", this->GetCertificateName().c_str(), validationResult);

		return validationResult;
	}


	//class BriandTorCertificate_Ed25519SigningKey : public BriandTorEd25519CertificateBase {

	string BriandTorCertificate_Ed25519SigningKey::GetCertificateName() { return "Ed25519SigningKey certificate"; }

	bool BriandTorCertificate_Ed25519SigningKey::IsValid(const BriandTorCertificate_RSAEd25519CrossCertificate& signAuthenticator) {
		if (this->IsExpired()) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519SigningKey is expired.\n");
			return false;
		}
			
		/* 
			As in certs-spec note, if ANY EdCertificaate has extension of type 04 (Signed-with-ed25519-key extension) then:
			When this extension is present, it MUST match the key used to sign the certificate.
			Actually I found that extension is used only in CertType 4 that is signed by the cross-cert. So check this.
			In this cert the signing key must match the ed key in the cross-certificate.
		*/
		if (this->EXTENSIONS->size() > 0) {
			for (auto& e : *this->EXTENSIONS.get()) {
				if (e.ExtType == 0x04) {
					if (e.ExtData->size() != signAuthenticator.ED25519_KEY->size() || 
						!std::equal(e.ExtData->begin(), e.ExtData->end(), signAuthenticator.ED25519_KEY->begin()) 
						) {
						ESP_LOGD(LOGTAG, "[DEBUG] Error, Ed25519SigningKey has extension 0x04 not matching the ED25519_KEY in the RSAEd25519CrossCertificate. Validation fails!\n");
						return false;
					}
				}
			}
		}

		// Check if signed by RSAEd25519CrossCertificate
		if (!this->IsSignatureIsValid(signAuthenticator.ED25519_KEY)) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519SigningKey has invalid signature.\n");
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Ed25519SigningKey is valid.\n");

		return true;
	}


	//class BriandTorCertificate_TLSLink : public BriandTorEd25519CertificateBase {

	string BriandTorCertificate_TLSLink::GetCertificateName() { return "TLSLink certificate"; }

	bool BriandTorCertificate_TLSLink::IsValid(const BriandTorCertificate_Ed25519SigningKey& signAuthenticator, const BriandTorCertificate_LinkKey& linkKeyCert) {
		if (this->IsExpired()) {
			ESP_LOGD(LOGTAG, "[DEBUG] TLSLink is expired.\n");
			return false;
		}
			
		if (!this->IsSignatureIsValid(signAuthenticator.CERTIFIED_KEY)) {
			ESP_LOGD(LOGTAG, "[DEBUG] TLSLink has invalid signature.\n");
			return false;
		}

		/* The certified key in the Signing->Link certificate matches the SHA256 digest of the certificate that was used to authenticate the TLS connection */

		auto linkKeyDigest = BriandTorCryptoUtils::GetDigest_SHA256(linkKeyCert.Contents);

		if (this->CERTIFIED_KEY->size() != linkKeyDigest->size() || 
			!std::equal(CERTIFIED_KEY->begin(), CERTIFIED_KEY->end(), linkKeyDigest->begin()) 
			) {
			ESP_LOGD(LOGTAG, "[DEBUG] Error, the SHA256 digest of LinkCertificate does not match the CertifiedKey.\n");
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] TLSLink is valid.\n");

		return true;
	}


	//class BriandTorCertificate_Ed25519AuthenticateCellLink : public BriandTorEd25519CertificateBase {

	string BriandTorCertificate_Ed25519AuthenticateCellLink::GetCertificateName() { return "Ed25519AuthenticateCellLink certificate"; }

	bool BriandTorCertificate_Ed25519AuthenticateCellLink::IsValid(const BriandTorCertificate_Ed25519SigningKey& signAuthenticator) {
		if (this->IsExpired()) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519AuthenticateCellLink is expired.\n");
			return false;
		}
			
		if (!this->IsSignatureIsValid(signAuthenticator.CERTIFIED_KEY)) {
			ESP_LOGD(LOGTAG, "[DEBUG] Ed25519AuthenticateCellLink has invalid signature.\n");
			return false;
		}

		//
		// TODO
		//

		ESP_LOGD(LOGTAG, "[DEBUG] Ed25519AuthenticateCellLink HAS NO WRITTEN VALIDATION METHODS (only signature and expiration is checked) !!!!!!!!!!!!\n");

		//
		// TODO
		//


		ESP_LOGD(LOGTAG, "[DEBUG] Ed25519AuthenticateCellLink is valid.\n");

		return true;
	}

}