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
#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandTorDirAuthority.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorCertificates.hxx"
#include "BriandTorCryptoUtils.hxx"

using namespace std;

namespace Briand {

	const char* BriandTorRelay::LOGTAG = "briandrelay";

	BriandTorRelay::BriandTorRelay() {
		this->nickname = make_unique<string>("");
		this->address = make_unique<string>("");
		this->fingerprint = make_unique<string>("");
		this->flags = 0x0000;
		//this->effective_family = make_unique<string>("");
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
		//this->effective_family.reset();

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

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Relay has Ed25519+RSA identity keys.\n");
			#endif

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
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid number of certificates.\n");
				#endif
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
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid or expired X.509 certificates.\n");
				#endif
				return false;
			}

			// Check for Ed25519 certificates

			/* The certified key in the ID certificate is a 1024-bit RSA key. */
			unsigned short keyLen = this->certRsa1024Identity->GetRsaKeyLength();
			if (keyLen != 1024) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", keyLen);
				#endif
				return false;
			}

			/* The RSA->Ed25519 cross-certificate certifies the Ed25519 identity, and is signed with the RSA identity listed in the "ID" certificate. */
			if (!this->certRSAEd25519CrossCertificate->IsValid( *this->certRsa1024Identity.get() )) 
			{
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Error, RSAEd25519CrossCertificate is expired or not correctly signed by RSA identity.\n");
				#endif
				return false;
			}

			/* 
				* The Signing->Link cert was signed with the Signing key listed in the ID->Signing cert. (CertType 5 Ed25519 is validated by CertType 4 Ed25519) 
				* The certified key in the Signing->Link certificate matches the SHA256 digest of the certificate that was used to authenticate the TLS connection. 
					(CertType 5 Ed25519 certified_key must match sha256 of the CertType 1/LinkKey)
			*/

			if (!this->certTLSLink->IsValid( *this->certEd25519SigningKey.get(), *this->certLinkKey.get() )) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Error, TLS Link is expired, not correctly signed by RSA identity or included certified key not matching SHA256 digest of Link certificate.\n");
				#endif
				return false;
			}

			/* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection. (CertType 5 Ed25519) */
			
			// This is not understood, unclear. The Link (certype 5) certified key contains the sha256 digest of the full content of the link (certtype 1) certificate :/

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] WARNING: this test is skipped because unclear: \"The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection.\"\n");
			#endif
			// TODO

			/* The identity key listed in the ID->Signing cert was used to sign the ID->Signing Cert. (CertType 4 Ed25519) */
			if (!this->certEd25519SigningKey->IsValid( *this->certRSAEd25519CrossCertificate.get() )) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Error, Ed25519SigningKey is expired or not correctly signed by RSAEd25519CrossCertificate's ED25519KEY.\n");
				#endif
				return false;
			}

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Relay with RSA+Ed25519 identity has the right and valid certificates.\n");
			#endif
			
			return true;
		}
		else if (this->certRsa1024Identity != nullptr) {
			/*
				To authenticate the responder as having a given RSA identity only,
				the initiator MUST check the following:
			*/

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Relay has RSA identity key only.\n");
			#endif

			/*
				* The CERTS cell contains exactly one CertType 1 "Link" certificate.
				* The CERTS cell contains exactly one CertType 2 "ID" certificate.
			*/

			if (this->certRsa1024Identity == nullptr || this->certLinkKey == nullptr ) 
			{
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid number of certificates.\n");
				#endif
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
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Relay has invalid or expired X.509 certificates.\n");
				#endif
				return false;
			}
	
			/*	The certified key in the ID certificate is a 1024-bit RSA key. */
			unsigned short keyLen = this->certRsa1024Identity->GetRsaKeyLength();
			if (keyLen != 1024) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", keyLen);
				#endif
				return false;
			}

			/* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection. */

			// 
			// TODO
			//

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Relay with RSA identity key only has the right and valid certificates.\n");
			#endif

			return true;
		}
		else {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Relay has no valid certificates to verify (no identity)!\n");
			#endif
			return false;
		}

		/*
			In both cases above, checking these conditions is sufficient to
			authenticate that the initiator is talking to the Tor node with the
			expected identity, as certified in the ID certificate(s).
		*/
	}

	bool BriandTorRelay::FetchDescriptorsFromAuthority() {
		// Start from the last used dir, do not create infinite loop
		bool success = false;
		unsigned short startingDir = TOR_DIR_LAST_USED;
		auto client = make_unique<BriandIDFSocketClient>();
		client->SetVerbose(false);
		client->SetID(100);
		client->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		do {
			success = false;
			this->descriptorNtorOnionKey->assign("");
			auto curDir = TOR_DIR_AUTHORITIES[TOR_DIR_LAST_USED];

			if (!client->Connect(string(curDir.host), curDir.port)) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority Failed to connect to dir #%hu (%s)\n", TOR_DIR_LAST_USED, curDir.nickname);
				#endif
				TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED+1) % TOR_DIR_AUTHORITIES_NUMBER;
				client->Disconnect();
				continue;
			}

			string agent = string(BriandUtils::GetRandomHostName().get());

			auto request = make_unique<string>();
			request->append("GET /tor/server/fp/" + *this->fingerprint.get() + " HTTP/1.1\r\n");
			request->append("Host: " + string(curDir.host) + "\r\n");
			request->append("User-Agent: " + agent);
			request->append("\r\n");
			request->append("Connection: close\r\n");
			request->append("\r\n");

			auto requestV = BriandNet::StringToUnsignedCharVector(request, true);

			if (!client->WriteData(requestV)) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority Failed to write request to dir #%hu (%s)\n", TOR_DIR_LAST_USED, curDir.nickname);
				#endif
				TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED+1) % TOR_DIR_AUTHORITIES_NUMBER;
				client->Disconnect();
				continue;
			}

			// free ram
			requestV.reset();

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] FetchDescriptorsFromAuthority request sent.\n");
			#endif

			bool newLine;
			do {
				auto lineV = client->ReadDataUntil('\n', 512, newLine);
				if (newLine) {
					auto line = BriandNet::UnsignedCharVectorToString(lineV, true);
					// Remove any \r
					BriandUtils::StringTrimAll(*line.get(), '\r');
					size_t starts;
					// Find the ntor-onion-key 
					starts = line->find("ntor-onion-key ");
					if (starts != string::npos) {
						starts = starts + 15;
						line->erase(0, starts);
						// If line has \n or \r remove
						BriandUtils::StringTrimAll(*line.get(), '\r');
						BriandUtils::StringTrimAll(*line.get(), '\n');
						this->descriptorNtorOnionKey->assign( line->c_str() );
						success = true;
					}
				}
			} while (newLine);

			// Disconnect client
			client->Disconnect();

			if (!success) TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED+1) % TOR_DIR_AUTHORITIES_NUMBER;
		} while (!success && startingDir != TOR_DIR_LAST_USED);

		// WARNING: base64 fields could be without the ending '=' but this could be not
		// recognized by a decoding library. So, add the ending '='/'==' to fit
		// the base64 multiples of 4 as required. (occours in ntor-onion-key)

		if (this->descriptorNtorOnionKey->length() > 0) {
			while (this->descriptorNtorOnionKey->length() % 4 != 0)
				this->descriptorNtorOnionKey->push_back('=');
		}

		return success;
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
		this->CREATED_EXTENDED_RESPONSE_SERVER_PK->reserve(G_LENGTH);
		this->CREATED_EXTENDED_RESPONSE_SERVER_PK->insert(
				this->CREATED_EXTENDED_RESPONSE_SERVER_PK->begin(), 
				created2_extended2_payload->begin() + 2, 
				created2_extended2_payload->begin() + 2 + G_LENGTH
			);
		
		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Relay's PK: ");
			BriandUtils::PrintByteBuffer(*this->CREATED_EXTENDED_RESPONSE_SERVER_PK.get(), this->CREATED_EXTENDED_RESPONSE_SERVER_PK->size(), this->CREATED_EXTENDED_RESPONSE_SERVER_PK->size());
		}
		#endif

		// And the other H_LENGTH 32 bytes
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH = make_unique<vector<unsigned char>>();
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->reserve(H_LENGTH);
		this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->insert(
				this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->begin(), 
				created2_extended2_payload->begin() + 2 + G_LENGTH, 
				created2_extended2_payload->begin() + 2 + G_LENGTH + H_LENGTH
			);

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Relay's AUTH: ");
			BriandUtils::PrintByteBuffer(*this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH.get(), this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size(), this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size());
		}
		#endif

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
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] The handshake is failed, no keys have been exchanged.\n");
			#endif
			return false;
		}

		#if !SUPPRESSDEBUGLOG
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
		#endif

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

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			if (this->certLinkKey != nullptr) this->certLinkKey->PrintCertInfo();
			if (this->certRsa1024Identity != nullptr) this->certRsa1024Identity->PrintCertInfo();
			if (this->certRsa1024AuthenticateCell != nullptr) this->certRsa1024AuthenticateCell->PrintCertInfo();
			if (this->certEd25519SigningKey != nullptr) this->certEd25519SigningKey->PrintCertInfo();
			if (this->certTLSLink != nullptr) this->certTLSLink->PrintCertInfo();
			if (this->certEd25519AuthenticateCellLink != nullptr) this->certEd25519AuthenticateCellLink->PrintCertInfo();
			if (this->certRSAEd25519CrossCertificate != nullptr) this->certRSAEd25519CrossCertificate->PrintCertInfo();
		}
		#endif

	}

	void BriandTorRelay::ResetCertificates() {
		if(this->certLinkKey != nullptr) this->certLinkKey.reset();
		if(this->certRsa1024Identity != nullptr) this->certRsa1024Identity.reset();
		if(this->certRsa1024AuthenticateCell != nullptr) this->certRsa1024AuthenticateCell.reset();
		if(this->certEd25519SigningKey != nullptr) this->certEd25519SigningKey.reset();
		if(this->certTLSLink != nullptr) this->certTLSLink.reset();
		if(this->certEd25519AuthenticateCellLink != nullptr) this->certEd25519AuthenticateCellLink.reset();
		if(this->certRSAEd25519CrossCertificate != nullptr) this->certRSAEd25519CrossCertificate.reset();
	}

	void BriandTorRelay::PrintRelayInfo() {

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Nickame: %s\n", this->nickname->c_str());
			printf("[DEBUG] Address: %s\n", this->address->c_str());
			printf("[DEBUG] OR Port: %u\n", this->port);
			printf("[DEBUG] Fingerprint: %s\n", this->fingerprint->c_str());
			//printf("[DEBUG] Effective Family (raw contents): %s\n", this->effective_family->c_str());
			printf("[DEBUG] Encoded descriptor NTOR onion key: %s\n", this->descriptorNtorOnionKey->c_str());
			printf("[DEBUG] Decoded descriptor NTOR onion key: ");
			auto dec = BriandTorCryptoUtils::Base64Decode(*this->descriptorNtorOnionKey.get());
			BriandUtils::PrintByteBuffer(*dec.get(), dec->size(), dec->size());
		}
		#endif
		
	}

	size_t BriandTorRelay::GetObjectSize() {
		size_t oSize = 0;

		oSize += sizeof(*this);
		oSize += sizeof(this->address) + (this->address == nullptr ? 0 : this->address->size() * sizeof(char));
		oSize += sizeof(this->AES_BackwardContext) + (this->AES_BackwardContext == nullptr ? 0 : sizeof(*this->AES_BackwardContext.get()));
		oSize += sizeof(this->AES_BackwardIV) + (this->AES_BackwardIV == nullptr ? 0 : sizeof(*this->AES_BackwardIV)*16);
		oSize += sizeof(this->AES_BackwardNonceCounter) + (this->AES_BackwardNonceCounter == nullptr ? 0 : sizeof(*this->AES_BackwardNonceCounter)*16);
		oSize += sizeof(this->AES_ForwardContext) + (this->AES_ForwardContext == nullptr ? 0 : sizeof(*this->AES_ForwardContext.get()));
		oSize += sizeof(this->AES_ForwardIV) + (this->AES_ForwardIV == nullptr ? 0 : sizeof(*this->AES_ForwardIV)*16);
		oSize += sizeof(this->AES_ForwardNonceCounter) + (this->AES_ForwardNonceCounter == nullptr ? 0 : sizeof(*this->AES_ForwardNonceCounter)*16);
		oSize += sizeof(this->certEd25519AuthenticateCellLink) + (this->certEd25519AuthenticateCellLink == nullptr ? 0 : this->certEd25519AuthenticateCellLink->GetObjectSize());
		oSize += sizeof(this->certEd25519SigningKey) + (this->certEd25519SigningKey == nullptr ? 0 : this->certEd25519SigningKey->GetObjectSize());
		oSize += sizeof(this->certLinkKey) + (this->certLinkKey == nullptr ? 0 : this->certLinkKey->GetObjectSize());
		oSize += sizeof(this->certRsa1024AuthenticateCell) + (this->certRsa1024AuthenticateCell == nullptr ? 0 : this->certRsa1024AuthenticateCell->GetObjectSize());
		oSize += sizeof(this->certRsa1024Identity) + (this->certRsa1024Identity == nullptr ? 0 : this->certRsa1024Identity->GetObjectSize());
		oSize += sizeof(this->certRSAEd25519CrossCertificate) + (this->certRSAEd25519CrossCertificate == nullptr ? 0 : this->certRSAEd25519CrossCertificate->GetObjectSize());
		oSize += sizeof(this->certTLSLink) + (this->certTLSLink == nullptr ? 0 : this->certTLSLink->GetObjectSize());
		oSize += sizeof(this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH) + (this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH == nullptr ? 0 : this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size() * sizeof(unsigned char));
		oSize += sizeof(this->CREATED_EXTENDED_RESPONSE_SERVER_PK) + (this->CREATED_EXTENDED_RESPONSE_SERVER_PK == nullptr ? 0 : this->CREATED_EXTENDED_RESPONSE_SERVER_PK->size() * sizeof(unsigned char));
		oSize += sizeof(this->CURVE25519_PRIVATE_KEY) + (this->CURVE25519_PRIVATE_KEY == nullptr ? 0 : this->CURVE25519_PRIVATE_KEY->size() * sizeof(unsigned char));
		oSize += sizeof(this->CURVE25519_PUBLIC_KEY) + (this->CURVE25519_PUBLIC_KEY == nullptr ? 0 : this->CURVE25519_PUBLIC_KEY->size() * sizeof(unsigned char));
		oSize += sizeof(this->descriptorNtorOnionKey) + (this->descriptorNtorOnionKey == nullptr ? 0 : this->descriptorNtorOnionKey->size() * sizeof(char));
		oSize += sizeof(this->fingerprint) + (this->fingerprint == nullptr ? 0 : this->fingerprint->size() * sizeof(char));
		oSize += sizeof(this->KEY_Backward_Kb) + (this->KEY_Backward_Kb == nullptr ? 0 : this->KEY_Backward_Kb->size() * sizeof(unsigned char));
		oSize += sizeof(this->KEY_BackwardDigest_Db) + (this->KEY_BackwardDigest_Db == nullptr ? 0 : sizeof(*KEY_BackwardDigest_Db.get()));
		oSize += sizeof(this->KEY_Forward_Kf) + (this->KEY_Forward_Kf == nullptr ? 0 : this->KEY_Forward_Kf->size() * sizeof(unsigned char));
		oSize += sizeof(this->KEY_ForwardDigest_Df) + (this->KEY_ForwardDigest_Df == nullptr ? 0 : sizeof(*KEY_ForwardDigest_Df.get()));
		oSize += sizeof(this->KEY_HiddenService_Nonce) + (this->KEY_HiddenService_Nonce == nullptr ? 0 : this->KEY_HiddenService_Nonce->size() * sizeof(unsigned char));
		oSize += sizeof(this->KEYSEED) + (this->KEYSEED == nullptr ? 0 : this->KEYSEED->size() * sizeof(unsigned char));
		oSize += sizeof(this->nickname) + (this->nickname == nullptr ? 0 : this->nickname->size() * sizeof(char));

		return oSize;
	}

	void BriandTorRelay::PrintObjectSizeInfo() {
		printf("sizeof(*this) = %zu\n", sizeof(*this));
		printf("sizeof(this->address) = %zu\n", sizeof(this->address) + (this->address == nullptr ? 0 : this->address->size() * sizeof(char)));
		printf("sizeof(this->AES_BackwardContext) = %zu\n", sizeof(this->AES_BackwardContext) + (this->AES_BackwardContext == nullptr ? 0 : sizeof(*this->AES_BackwardContext.get())));
		printf("sizeof(this->AES_BackwardIV) = %zu\n", sizeof(this->AES_BackwardIV) + (this->AES_BackwardIV == nullptr ? 0 : sizeof(*this->AES_BackwardIV)*16));
		printf("sizeof(this->AES_BackwardNonceCounter) = %zu\n", sizeof(this->AES_BackwardNonceCounter) + (this->AES_BackwardNonceCounter == nullptr ? 0 : sizeof(*this->AES_BackwardNonceCounter)*16));
		printf("sizeof(this->AES_BackwardNonceOffset) = %zu\n", sizeof(this->AES_BackwardNonceOffset));
		printf("sizeof(this->AES_ForwardContext) = %zu\n", sizeof(this->AES_ForwardContext) + (this->AES_ForwardContext == nullptr ? 0 : sizeof(*this->AES_ForwardContext.get())));
		printf("sizeof(this->AES_ForwardIV) = %zu\n", sizeof(this->AES_ForwardIV) + (this->AES_ForwardIV == nullptr ? 0 : sizeof(*this->AES_ForwardIV)*16));
		printf("sizeof(this->AES_ForwardNonceCounter) = %zu\n", sizeof(this->AES_ForwardNonceCounter) + (this->AES_ForwardNonceCounter == nullptr ? 0 : sizeof(*this->AES_ForwardNonceCounter)*16));
		printf("sizeof(this->AES_ForwardNonceOffset) = %zu\n", sizeof(this->AES_ForwardNonceOffset));
		printf("sizeof(this->certEd25519AuthenticateCellLink) = %zu\n", sizeof(this->certEd25519AuthenticateCellLink) + (this->certEd25519AuthenticateCellLink == nullptr ? 0 : this->certEd25519AuthenticateCellLink->GetObjectSize()));
		printf("sizeof(this->certEd25519SigningKey) = %zu\n", sizeof(this->certEd25519SigningKey) + (this->certEd25519SigningKey == nullptr ? 0 : this->certEd25519SigningKey->GetObjectSize()));
		printf("sizeof(this->certLinkKey) = %zu\n", sizeof(this->certLinkKey) + (this->certLinkKey == nullptr ? 0 : this->certLinkKey->GetObjectSize()));
		printf("sizeof(this->certRsa1024AuthenticateCell) = %zu\n", sizeof(this->certRsa1024AuthenticateCell) + (this->certRsa1024AuthenticateCell == nullptr ? 0 : this->certRsa1024AuthenticateCell->GetObjectSize()));
		printf("sizeof(this->certRsa1024Identity) = %zu\n", sizeof(this->certRsa1024Identity) + (this->certRsa1024Identity == nullptr ? 0 : this->certRsa1024Identity->GetObjectSize()));
		printf("sizeof(this->certRSAEd25519CrossCertificate) = %zu\n", sizeof(this->certRSAEd25519CrossCertificate) + (this->certRSAEd25519CrossCertificate == nullptr ? 0 : this->certRSAEd25519CrossCertificate->GetObjectSize()));
		printf("sizeof(this->certTLSLink) = %zu\n", sizeof(this->certTLSLink) + (this->certTLSLink == nullptr ? 0 : this->certTLSLink->GetObjectSize()));
		printf("sizeof(this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH) = %zu\n", sizeof(this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH) + (this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH == nullptr ? 0 : this->CREATED_EXTENDED_RESPONSE_SERVER_AUTH->size() * sizeof(unsigned char)));
		printf("sizeof(this->CREATED_EXTENDED_RESPONSE_SERVER_PK) = %zu\n", sizeof(this->CREATED_EXTENDED_RESPONSE_SERVER_PK) + (this->CREATED_EXTENDED_RESPONSE_SERVER_PK == nullptr ? 0 : this->CREATED_EXTENDED_RESPONSE_SERVER_PK->size() * sizeof(unsigned char)));
		printf("sizeof(this->CURVE25519_PRIVATE_KEY) = %zu\n", sizeof(this->CURVE25519_PRIVATE_KEY) + (this->CURVE25519_PRIVATE_KEY == nullptr ? 0 : this->CURVE25519_PRIVATE_KEY->size() * sizeof(unsigned char)));
		printf("sizeof(this->CURVE25519_PUBLIC_KEY) = %zu\n", sizeof(this->CURVE25519_PUBLIC_KEY) + (this->CURVE25519_PUBLIC_KEY == nullptr ? 0 : this->CURVE25519_PUBLIC_KEY->size() * sizeof(unsigned char)));
		printf("sizeof(this->descriptorNtorOnionKey) = %zu\n", sizeof(this->descriptorNtorOnionKey) + (this->descriptorNtorOnionKey == nullptr ? 0 : this->descriptorNtorOnionKey->size() * sizeof(char)));
		printf("sizeof(this->fingerprint) = %zu\n", sizeof(this->fingerprint) + (this->fingerprint == nullptr ? 0 : this->fingerprint->size() * sizeof(char)));
		printf("sizeof(this->KEY_Backward_Kb) = %zu\n", sizeof(this->KEY_Backward_Kb) + (this->KEY_Backward_Kb == nullptr ? 0 : this->KEY_Backward_Kb->size() * sizeof(unsigned char)));
		printf("sizeof(this->KEY_BackwardDigest_Db) = %zu\n", sizeof(this->KEY_BackwardDigest_Db) + (this->KEY_BackwardDigest_Db == nullptr ? 0 : sizeof(*KEY_BackwardDigest_Db.get())));
		printf("sizeof(this->KEY_Forward_Kf) = %zu\n", sizeof(this->KEY_Forward_Kf) + (this->KEY_Forward_Kf == nullptr ? 0 : this->KEY_Forward_Kf->size() * sizeof(unsigned char)));
		printf("sizeof(this->KEY_ForwardDigest_Df) = %zu\n", sizeof(this->KEY_ForwardDigest_Df) + (this->KEY_ForwardDigest_Df == nullptr ? 0 : sizeof(*KEY_ForwardDigest_Df.get())));
		printf("sizeof(this->KEY_HiddenService_Nonce) = %zu\n", sizeof(this->KEY_HiddenService_Nonce) + (this->KEY_HiddenService_Nonce == nullptr ? 0 : this->KEY_HiddenService_Nonce->size() * sizeof(unsigned char)));
		printf("sizeof(this->KEYSEED) = %zu\n", sizeof(this->KEYSEED) + (this->KEYSEED == nullptr ? 0 : this->KEYSEED->size() * sizeof(unsigned char)));
		printf("sizeof(this->nickname) = %zu\n", sizeof(this->nickname) + (this->nickname == nullptr ? 0 : this->nickname->size() * sizeof(char)));

		printf("TOTAL = %zu\n", this->GetObjectSize());
	}

}