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

#include "BriandTorRelay.hxx"

#include <iostream>
#include <memory>
#include <sstream>
#include <vector>
#include <algorithm>

// Crypto library chosen
#include <mbedtls/ecdh.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandTorDirAuthority.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorCertificates.hxx"
#include "BriandTorCryptoUtils.hxx"

using namespace std;

namespace Briand {

	BriandTorRelay::BriandTorRelay() {
		this->nickname = make_unique<string>("");
		this->address = make_unique<string>("");
		this->fingerprint = make_unique<string>("");
		this->flags = 0x0000;
		this->effective_family = make_unique<string>("");
		this->descriptorNtorOnionKey = make_unique<string>("");
		this->certLinkKey = nullptr;
		this->certRsa1024Identity = nullptr;
		this->certRsa1024AuthenticateCell = nullptr;
		this->certEd25519SigningKey = nullptr;
		this->certTLSLink = nullptr;
		this->certEd25519AuthenticateCellLink = nullptr;
		this->certRSAEd25519CrossCertificate = nullptr;
		this->CURVE25519_PRIVATE_KEY = nullptr;
		this->CURVE25519_PUBLIC_KEY = nullptr;
		this->CREATED_EXTENDED_RESPONSE_SERVER_PK = nullptr;
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH = nullptr;
		this->KEYSEED = nullptr;
		this->KEY_Backward_Kb = nullptr;
		this->KEY_BackwardDigest_Db = nullptr;
		this->KEY_Forward_Kf = nullptr;
		this->KEY_ForwardDigest_Df = nullptr;
		this->KEY_HiddenService_Nonce = nullptr;
		this->AES_ForwardContext = make_unique<esp_aes_context>();
		this->AES_BackwardContext = make_unique<esp_aes_context>();
	}

	BriandTorRelay::~BriandTorRelay() {
		this->nickname.reset();
		this->address.reset();
		this->fingerprint.reset();
		this->effective_family.reset();

		if(this->certLinkKey != nullptr) this->certLinkKey.reset();
		if(this->certRsa1024Identity != nullptr) this->certRsa1024Identity.reset();
		if(this->certRsa1024AuthenticateCell != nullptr) this->certRsa1024AuthenticateCell.reset();
		if(this->certEd25519SigningKey != nullptr) this->certEd25519SigningKey.reset();
		if(this->certTLSLink != nullptr) this->certTLSLink.reset();
		if(this->certEd25519AuthenticateCellLink != nullptr) this->certEd25519AuthenticateCellLink.reset();
		if(this->certRSAEd25519CrossCertificate != nullptr) this->certRSAEd25519CrossCertificate.reset();
		if(this->CURVE25519_PRIVATE_KEY != nullptr) this->CURVE25519_PRIVATE_KEY.reset();
		if(this->CURVE25519_PUBLIC_KEY != nullptr) this->CURVE25519_PUBLIC_KEY.reset();
		if(this->CREATED_EXTENDED_RESPONSE_SERVER_PK != nullptr) this->CREATED_EXTENDED_RESPONSE_SERVER_PK.reset();
		if(this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH != nullptr) this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH.reset();
		if(this->KEYSEED != nullptr) this->KEYSEED.reset();
		if(this->KEY_Backward_Kb != nullptr) this->KEY_Backward_Kb.reset();
		if(this->KEY_BackwardDigest_Db != nullptr) {
			// mbedtls must free
			mbedtls_md_free(this->KEY_BackwardDigest_Db.get());
			this->KEY_BackwardDigest_Db.reset();
		}
		if(this->KEY_Forward_Kf != nullptr) this->KEY_Forward_Kf.reset();
		if(this->KEY_ForwardDigest_Df != nullptr) {
			// mbedtls must free
			mbedtls_md_free(this->KEY_ForwardDigest_Df.get());
			this->KEY_ForwardDigest_Df.reset();
		}
		if(this->KEY_HiddenService_Nonce != nullptr) this->KEY_HiddenService_Nonce.reset();
		if (this->AES_ForwardContext != nullptr) {
			esp_aes_free(this->AES_ForwardContext.get());
			this->AES_ForwardContext.reset();
		}
		if (this->AES_BackwardContext != nullptr) {
			esp_aes_free(this->AES_BackwardContext.get());
			this->AES_BackwardContext.reset();
		}
	}

	string BriandTorRelay::GetHost() {
		return *this->address.get();
	}

	unsigned short BriandTorRelay::GetPort() {
		return this->port;
	}

	unsigned short BriandTorRelay::GetCertificateCount() {
		unsigned short num = 0x0000;

		if (this->certEd25519AuthenticateCellLink != nullptr) num++;
		if (this->certEd25519SigningKey != nullptr) num++;
		if (this->certLinkKey != nullptr) num++;
		if (this->certRsa1024AuthenticateCell != nullptr) num++;
		if (this->certRsa1024Identity != nullptr) num++;
		if (this->certRSAEd25519CrossCertificate != nullptr) num++;
		if (this->certTLSLink != nullptr) num++;

		return num;
	}

	bool BriandTorRelay::ValidateCertificates() {
		
		if (this->certRsa1024Identity != nullptr && this->certRSAEd25519CrossCertificate != nullptr) {
			/*			
				To authenticate the responder as having a given Ed25519,RSA identity key
				combination, the initiator MUST check the following.
			*/

			ESP_LOGD(LOGTAG, "[DEBUG] Relay has Ed25519+RSA identity keys.\n");

			/*
				* The CERTS cell contains exactly one CertType 2 "ID" certificate.
				* The CERTS cell contains exactly one CertType 4 Ed25519 "Id->Signing" cert.
				* The CERTS cell contains exactly one CertType 5 Ed25519 "Signing->link" certificate.
				* The CERTS cell contains exactly one CertType 7 "RSA->Ed25519" cross-certificate.
			*/

			// Exactly one... skipped by construction. Also another cert must be present, the RSA CertType1 LinkKey 
			// I think in future this may change

			if (this->certRsa1024Identity == nullptr ||
				this->certLinkKey == nullptr ||
				this->certEd25519SigningKey == nullptr ||
				this->certTLSLink == nullptr ||
				this->certRSAEd25519CrossCertificate == nullptr ) 
			{
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid number of certificates.\n");
				return false;
			}

			/*
				* All X.509 certificates above have validAfter and validUntil dates; no X.509 or Ed25519 certificates are expired.
				* All certificates are correctly signed.
				* The RSA ID certificate is correctly self-signed.
			*/

			// Expiration dates are always verified by any IsValid method
			// Sign verification is done cert-by-cert by IsValid method

			// Check for X509 types (1,2,3)
			if (!this->certRsa1024Identity->IsValid() ||
				!this->certLinkKey->IsValid( *this->certRsa1024Identity.get() ) ||
				(this->certRsa1024AuthenticateCell != nullptr && !this->certRsa1024AuthenticateCell->IsValid( *this->certRsa1024Identity.get() ))
				) 
			{
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid or expired X.509 certificates.\n");
				return false;
			}

			// Check for Ed25519 certificates

			/* The certified key in the ID certificate is a 1024-bit RSA key. */
			unsigned short keyLen = this->certRsa1024Identity->GetRsaKeyLength();
			if (keyLen != 1024) {
				ESP_LOGD(LOGTAG, "[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", keyLen);
				return false;
			}

			/* The RSA->Ed25519 cross-certificate certifies the Ed25519 identity, and is signed with the RSA identity listed in the "ID" certificate. */
			if (!this->certRSAEd25519CrossCertificate->IsValid( *this->certRsa1024Identity.get() )) 
			{
				ESP_LOGD(LOGTAG, "[DEBUG] Error, RSAEd25519CrossCertificate is expired or not correctly signed by RSA identity.\n");
				return false;
			}

			/* 
				* The Signing->Link cert was signed with the Signing key listed in the ID->Signing cert. (CertType 5 Ed25519 is validated by CertType 4 Ed25519) 
				* The certified key in the Signing->Link certificate matches the SHA256 digest of the certificate that was used to authenticate the TLS connection. 
					(CertType 5 Ed25519 certified_key must match sha256 of the CertType 1/LinkKey)
			*/

			if (!this->certTLSLink->IsValid( *this->certEd25519SigningKey.get(), *this->certLinkKey.get() )) {
				ESP_LOGD(LOGTAG, "[DEBUG] Error, TLS Link is expired, not correctly signed by RSA identity or included certified key not matching SHA256 digest of Link certificate.\n");
				return false;
			}

			/* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection. (CertType 5 Ed25519) */
			
			// This is not understood, unclear. The Link (certype 5) certified key contains the sha256 digest of the full content of the link (certtype 1) certificate :/

			ESP_LOGD(LOGTAG, "[DEBUG] WARNING: this test is skipped because unclear: \"The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection.\"\n");
			// TODO

			/* The identity key listed in the ID->Signing cert was used to sign the ID->Signing Cert. (CertType 4 Ed25519) */
			if (!this->certEd25519SigningKey->IsValid( *this->certRSAEd25519CrossCertificate.get() )) {
				ESP_LOGD(LOGTAG, "[DEBUG] Error, Ed25519SigningKey is expired or not correctly signed by RSAEd25519CrossCertificate's ED25519KEY.\n");
				return false;
			}

			ESP_LOGD(LOGTAG, "[DEBUG] Relay with RSA+Ed25519 identity has the right and valid certificates.\n");
			
			return true;
		}
		else if (this->certRsa1024Identity != nullptr) {
			/*
				To authenticate the responder as having a given RSA identity only,
				the initiator MUST check the following:
			*/

			ESP_LOGD(LOGTAG, "[DEBUG] Relay has RSA identity key only.\n");

			/*
				* The CERTS cell contains exactly one CertType 1 "Link" certificate.
				* The CERTS cell contains exactly one CertType 2 "ID" certificate.
			*/

			if (this->certRsa1024Identity == nullptr || this->certLinkKey == nullptr ) 
			{
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid number of certificates.\n");
				return false;
			}

			/*
				* Both certificates have validAfter and validUntil dates that are not expired.
				* The certified key in the ID certificate was used to sign both certificates.
				* The link certificate is correctly signed with the key in the ID certificate
				* The ID certificate is correctly self-signed.
			*/

			if (!this->certRsa1024Identity->IsValid() ||
				!this->certLinkKey->IsValid( *this->certRsa1024Identity.get() ) ||
				(this->certRsa1024AuthenticateCell != nullptr && !this->certRsa1024AuthenticateCell->IsValid( *this->certRsa1024Identity.get() ))
				) 
			{
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid or expired X.509 certificates.\n");
				return false;
			}
	
			/*	The certified key in the ID certificate is a 1024-bit RSA key. */
			unsigned short keyLen = this->certRsa1024Identity->GetRsaKeyLength();
			if (keyLen != 1024) {
				ESP_LOGD(LOGTAG, "[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", keyLen);
				return false;
			}

			/* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection. */

			// 
			// TODO
			//

			ESP_LOGD(LOGTAG, "[DEBUG] Relay with RSA identity key only has the right and valid certificates.\n");

			return true;
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] Relay has no valid certificates to verify (no identity)!\n");
			return false;
		}

		/*
			In both cases above, checking these conditions is sufficient to
			authenticate that the initiator is talking to the Tor node with the
			expected identity, as certified in the ID certificate(s).
		*/
	}

	bool BriandTorRelay::FetchDescriptorsFromAuthority() {
		// Call via http
		unique_ptr<string> response = nullptr;
		string agent = string( BriandUtils::GetRandomHostName().get() );
		short httpCode;

		// Auth dir enquiry : choose a random one then enquiry another if one fails
		if (TOR_DIR_LAST_USED == 0x0000) {
			TOR_DIR_LAST_USED = BriandUtils::GetRandomByte() % TOR_DIR_AUTHORITIES_NUMBER;
		}

		unsigned short curDir = 0;

		while(httpCode != 200 && curDir < TOR_DIR_AUTHORITIES_NUMBER) {
			auto randomDirectory = TOR_DIR_AUTHORITIES[TOR_DIR_LAST_USED];
			ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority Query to dir #%u (%s).\n", TOR_DIR_LAST_USED, randomDirectory.nickname);

			string path = "/tor/server/fp/" + *this->fingerprint.get();	// also /tor/server/d/<F> working
			bool secureRequest = false;

			if (secureRequest)
				response = BriandNet::HttpsGet(randomDirectory.host, randomDirectory.port, path, httpCode, agent, false);
			else
				response = BriandNet::HttpInsecureGet(randomDirectory.host, randomDirectory.port, path, httpCode, agent, false);

			if (httpCode != 200) {
				curDir++;
				TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED + 1) % TOR_DIR_AUTHORITIES_NUMBER;
				ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority missed valid response, retry with dir #%u.\n", TOR_DIR_LAST_USED);
			}
		}

		if (httpCode == 200) {
			ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority GET success.\n");
			unsigned int starts, ends;

			// Find the ntor-onion-key 
			starts = response->find("ntor-onion-key ");
			ends = response->find("\n", starts);
			
			if (starts == string::npos || ends == string::npos) {
				ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority ntor-onion-key failed.\n");
				this->descriptorNtorOnionKey->assign("");
				return false;
			}
			else {
				this->descriptorNtorOnionKey->assign( response->substr(starts + 15, ends-starts) );

				// Clean up the string (sometimes missing \n in some nodes and also \r has been found :/)
				starts = this->descriptorNtorOnionKey->find("\n");
				while (starts != string::npos) {
					this->descriptorNtorOnionKey->erase(this->descriptorNtorOnionKey->begin()+starts, this->descriptorNtorOnionKey->end());
					starts = this->descriptorNtorOnionKey->find("\n");
				}
				starts = this->descriptorNtorOnionKey->find("\r");
				while (starts != string::npos) {
					this->descriptorNtorOnionKey->erase(this->descriptorNtorOnionKey->begin()+starts, this->descriptorNtorOnionKey->end());
					starts = this->descriptorNtorOnionKey->find("\r");
				}
			}

			// WARNING: base64 fields could be without the ending '=' but this could be not
			// recognized by a decoding library. So, add the ending '='/'==' to fit
			// the base64 multiples of 4 as required. (occours in ntor-onion-key)

			if (this->descriptorNtorOnionKey->length() > 0) {
				while (this->descriptorNtorOnionKey->length() % 4 != 0)
					this->descriptorNtorOnionKey->push_back('=');
			}

			// TODO : other descriptors needed??
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority has failed, httpcode: %d\n", httpCode);
			return false;
		}

		return true;
	}

	bool BriandTorRelay::FinishHandshake(const unique_ptr<vector<unsigned char>>& created2_extended2_payload) {
		/*
			A CREATED2 cell contains:

				HLEN      (Server Handshake Data Len) [2 bytes]
				HDATA     (Server Handshake Data)     [HLEN bytes]

			where HDATA with ntor protocol is:
			
			SERVER_PK   Y                       [G_LENGTH bytes] => 32 bytes
       		AUTH        H(auth_input, t_mac)    [H_LENGTH bytes] => 32 bytes
		*/

		// In future may change...
		constexpr unsigned int G_LENGTH = 32;
		constexpr unsigned int H_LENGTH = 32;

		// Check if data is enough WARNING: in future the length may change!
		if (created2_extended2_payload->size() < 2+G_LENGTH+H_LENGTH) {
			ESP_LOGW(LOGTAG, "[ERR] Error, CREATED2 contains inconsistent payload (%u bytes against %u expected). Failure.\n", created2_extended2_payload->size(), 2+G_LENGTH+H_LENGTH);
			return false;
		}

		unsigned short HLEN = 0;
		HLEN += static_cast<unsigned short>( created2_extended2_payload->at(0) << 8 );
		HLEN += static_cast<unsigned short>( created2_extended2_payload->at(1) );

		// Check HLEN consistent
		if (HLEN != G_LENGTH+H_LENGTH) {
			ESP_LOGW(LOGTAG, "[ERR] Error, CREATED2 contains inconsistent HLEN payload (%u bytes against %u expected). Failure.\n", HLEN, G_LENGTH+H_LENGTH);
			return false;
		}

		// Prepare and copy first G_LENGTH bytes
		this->CREATED_EXTENDED_RESPONSE_SERVER_PK = make_unique<vector<unsigned char>>();
		this->CREATED_EXTENDED_RESPONSE_SERVER_PK->insert(
				this->CREATED_EXTENDED_RESPONSE_SERVER_PK->begin(), 
				created2_extended2_payload->begin() + 2, 
				created2_extended2_payload->begin() + 2 + G_LENGTH
			);
		
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Relay's PK: ");
			BriandUtils::PrintByteBuffer(*this->CREATED_EXTENDED_RESPONSE_SERVER_PK.get(), this->CREATED_EXTENDED_RESPONSE_SERVER_PK->size(), this->CREATED_EXTENDED_RESPONSE_SERVER_PK->size());
		}

		// And the other H_LENGTH 32 bytes
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH = make_unique<vector<unsigned char>>();
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->insert(
				this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->begin(), 
				created2_extended2_payload->begin() + 2 + G_LENGTH, 
				created2_extended2_payload->begin() + 2 + G_LENGTH + H_LENGTH
			);

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Relay's AUTH: ");
			BriandUtils::PrintByteBuffer(*this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH.get(), this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size(), this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size());
		}

		// Prepare relay's fields if, for any error, were populated
		if(this->KEYSEED != nullptr) this->KEYSEED.reset();
		if(this->KEY_Backward_Kb != nullptr) this->KEY_Backward_Kb.reset();
		if(this->KEY_BackwardDigest_Db != nullptr) this->KEY_BackwardDigest_Db.reset();
		if(this->KEY_Forward_Kf != nullptr) this->KEY_Forward_Kf.reset();
		if(this->KEY_ForwardDigest_Df != nullptr) this->KEY_ForwardDigest_Df.reset();
		if(this->KEY_HiddenService_Nonce != nullptr) this->KEY_HiddenService_Nonce.reset();

		// Do the calculations needed to finish the handshake
		bool keysReady = BriandTorCryptoUtils::NtorHandshakeComplete(*this);

		if (!keysReady) {
			ESP_LOGD(LOGTAG, "[DEBUG] The handshake is failed, no keys have been exchanged.\n");
			return false;
		}

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Forward key: ");
			BriandUtils::PrintByteBuffer( *this->KEY_Forward_Kf.get() );
			printf("[DEBUG] Backward key: ");
			BriandUtils::PrintByteBuffer( *this->KEY_Backward_Kb.get() );
			//printf("[DEBUG] Forward digest seed: ");
			///BriandUtils::PrintByteBuffer( *this->KEY_ForwardDigest_Df.get() );
			//printf("[DEBUG] Backward digest seed: ");
			//BriandUtils::PrintByteBuffer( *this->KEY_BackwardDigest_Db.get() );
			printf("[DEBUG] Hidden service nonce: ");
			BriandUtils::PrintByteBuffer( *this->KEY_HiddenService_Nonce.get() );
		}

		// After that, clean no more needed fields!
		this->CREATED_EXTENDED_RESPONSE_SERVER_PK.reset();
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH.reset();
		this->KEYSEED.reset();

		// Also client-side context should be cleared and free (it was temporary)
		this->CURVE25519_PRIVATE_KEY.reset();
		this->CURVE25519_PUBLIC_KEY.reset();

		return keysReady;
	}

	void BriandTorRelay::PrintAllCertificateShortInfo() {
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			if (this->certLinkKey != nullptr) this->certLinkKey->PrintCertInfo();
			if (this->certRsa1024Identity != nullptr) this->certRsa1024Identity->PrintCertInfo();
			if (this->certRsa1024AuthenticateCell != nullptr) this->certRsa1024AuthenticateCell->PrintCertInfo();
			if (this->certEd25519SigningKey != nullptr) this->certEd25519SigningKey->PrintCertInfo();
			if (this->certTLSLink != nullptr) this->certTLSLink->PrintCertInfo();
			if (this->certEd25519AuthenticateCellLink != nullptr) this->certEd25519AuthenticateCellLink->PrintCertInfo();
			if (this->certRSAEd25519CrossCertificate != nullptr) this->certRSAEd25519CrossCertificate->PrintCertInfo();
			
		}
	}

	void BriandTorRelay::PrintRelayInfo() {
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Nickame: %s\n", this->nickname->c_str());
			printf("[DEBUG] Address: %s\n", this->address->c_str());
			printf("[DEBUG] OR Port: %u\n", this->port);
			printf("[DEBUG] Fingerprint: %s\n", this->fingerprint->c_str());
			printf("[DEBUG] Effective Family (raw contents): %s\n", this->effective_family->c_str());
			printf("[DEBUG] Encoded descriptor NTOR onion key: %s\n", this->descriptorNtorOnionKey->c_str());
			printf("[DEBUG] Decoded descriptor NTOR onion key: ");
			auto dec = BriandTorCryptoUtils::Base64Decode(*this->descriptorNtorOnionKey.get());
			BriandUtils::PrintByteBuffer(*dec.get(), dec->size(), dec->size());
		}
	}

}