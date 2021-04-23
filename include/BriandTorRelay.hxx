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
#include <vector>
#include <algorithm>

#include <ArduinoJson.h>
#include <WiFiClientSecure.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorCertificates.hxx"

using namespace std;

namespace Briand {
	/**
	 * This class describes and keeps information about a single Tor Relay
	*/
	class BriandTorRelay {
		private:
		protected:
		public:

		unique_ptr<string> nickname;
		unique_ptr<string> first_address;
		unique_ptr<string> fingerprint;
		unsigned short flags;

		/** Certificates for this relay (nullptr if not present) */
		unique_ptr<BriandTorCertificate_LinkKey> certLinkKey;
		unique_ptr<BriandTorCertificate_RSA1024Identity> certRsa1024Identity;
		unique_ptr<BriandTorCertificate_RSA1024AuthenticateCellLink> certRsa1024AuthenticateCell;
		unique_ptr<BriandTorCertificate_Ed25519SigningKey> certEd25519SigningKey;
		unique_ptr<BriandTorCertificate_TLSLink> certTLSLink;
		unique_ptr<BriandTorCertificate_Ed25519AuthenticateCellLink> certEd25519AuthenticateCellLink;
		unique_ptr<BriandTorCertificate_RSAEd25519CrossCertificate> certRSAEd25519CrossCertificate;

		// TODO: handle more fields (minimum necessary if needed!)

		// Relay Certificates (ready after a CERTS cell is sent)
		
		BriandTorRelay() {
			this->nickname = make_unique<string>("");
			this->first_address = make_unique<string>("");
			this->fingerprint = make_unique<string>("");
			this->flags = 0x0000;
			this->certLinkKey = nullptr;
			this->certRsa1024Identity = nullptr;
			this->certRsa1024AuthenticateCell = nullptr;
			this->certEd25519SigningKey = nullptr;
			this->certTLSLink = nullptr;
			this->certEd25519AuthenticateCellLink = nullptr;
			this->certRSAEd25519CrossCertificate = nullptr;
		}

		~BriandTorRelay() {
			this->nickname.reset();
			this->first_address.reset();
			this->fingerprint.reset();
			if(this->certLinkKey == nullptr) this->certLinkKey.reset();
			if(this->certRsa1024Identity == nullptr) this->certRsa1024Identity.reset();
			if(this->certRsa1024AuthenticateCell == nullptr) this->certRsa1024AuthenticateCell.reset();
			if(this->certEd25519SigningKey == nullptr) this->certEd25519SigningKey.reset();
			if(this->certTLSLink == nullptr) this->certTLSLink.reset();
			if(this->certEd25519AuthenticateCellLink == nullptr) this->certEd25519AuthenticateCellLink.reset();
			if(this->certRSAEd25519CrossCertificate == nullptr) this->certRSAEd25519CrossCertificate.reset();
		}

		/**
		 * Method returns relay host
		 * @return host in string format 
		*/
		string GetHost() {
			int sepPos = this->first_address->find(':');
			if (sepPos != std::string::npos) {
				return string( this->first_address->substr(0, sepPos) );
			}
			else
				return string("");
		}

		/**
		 * Method returns relay port
		 * @return port
		*/
		unsigned short GetPort() {
			int sepPos = this->first_address->find(':');
			if (sepPos != std::string::npos) {
				return stoi( this->first_address->substr(sepPos + 1 ) ); // from there to the end
			}
			else
				return 0;
		}
	
		unsigned short GetCertificateCount() {
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

		/**
		 * Method validates certificates as required in Tor handshake protocol.
		 * @return true if all valid, false if not.
		*/
		bool ValidateCertificates() {
			
			if (this->certRsa1024Identity != nullptr && this->certRSAEd25519CrossCertificate != nullptr) {
				/*			
					To authenticate the responder as having a given Ed25519,RSA identity key
					combination, the initiator MUST check the following.
				*/

				if (DEBUG) Serial.println("[DEBUG] Relay has Ed25519+RSA identity keys.");

				/*
					* The CERTS cell contains exactly one CertType 2 "ID" certificate.
					* The CERTS cell contains exactly one CertType 4 Ed25519 "Id->Signing" cert.
					* The CERTS cell contains exactly one CertType 5 Ed25519 "Signing->link" certificate.
					* The CERTS cell contains exactly one CertType 7 "RSA->Ed25519" cross-certificate.
				*/

				//
				// TODO
				//

				if (this->certRsa1024Identity == nullptr ||
					this->certEd25519SigningKey == nullptr ||
					this->certTLSLink == nullptr ||
					this->certRSAEd25519CrossCertificate == nullptr ) 
				{
					Serial.println("[DEBUG] Relay has invalid number of certificates.");
					return false;
				}

				/*
					* All X.509 certificates above have validAfter and validUntil dates; no X.509 or Ed25519 certificates are expired.
					* All certificates are correctly signed.
					* The RSA ID certificate is correctly self-signed.
				*/

				// Check for X509 types (1,2,3)
				if (!this->certRsa1024Identity->IsValid() ||
					!this->certLinkKey->IsValid( *this->certRsa1024Identity.get() ) ||
					(this->certRsa1024AuthenticateCell != nullptr && !this->certRsa1024AuthenticateCell->IsValid( *this->certRsa1024Identity.get() ))
					) 
				{
					Serial.println("[DEBUG] Relay has invalid or expired X.509 certificates.");
					return false;
				}

				// Check for Ed25519 certificates

				/* The certified key in the ID certificate is a 1024-bit RSA key. */
				unsigned short keyLen = this->certRsa1024Identity->GetRsaKeyLength();
				if (keyLen != 1024) {
					if (DEBUG) Serial.printf("[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", keyLen);
					return false;
				}

				/* The RSA->Ed25519 cross-certificate certifies the Ed25519 identity, and is signed with the RSA identity listed in the "ID" certificate. */
				if (!this->certRSAEd25519CrossCertificate->IsValid( *this->certRsa1024Identity.get() )) 
				{
					Serial.println("[DEBUG] Error, RSAEd25519CrossCertificate is expired or not correctly signed by RSA identity.");
					return false;
				}

				/*
					* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection.
				*/


				/*
					* The certified key in the Signing->Link certificate matches the SHA256 digest of the certificate that was used to authenticate the TLS connection. (CertType 5 Ed25519)
					* The identity key listed in the ID->Signing cert was used to sign the ID->Signing Cert. (CertType 4 Ed25519)
					* The Signing->Link cert was signed with the Signing key listed in the ID->Signing cert. (CertType 5 Ed25519)
					
				*/

				
				

				if (DEBUG) Serial.println("[DEBUG] Relay with RSA+Ed25519 identity has the right and valid certificates.");
				
				return true;
			}
			else if (this->certRsa1024Identity != nullptr) {
				/*
					To authenticate the responder as having a given RSA identity only,
					the initiator MUST check the following:
				*/

				if (DEBUG) Serial.println("[DEBUG] Relay has RSA identity key only.");

				/*
					* The CERTS cell contains exactly one CertType 1 "Link" certificate.
					* The CERTS cell contains exactly one CertType 2 "ID" certificate.
				*/

				if (this->certRsa1024Identity == nullptr || this->certLinkKey == nullptr ) 
				{
					Serial.println("[DEBUG] Relay has invalid number of certificates.");
					return false;
				}

				/*
					* Both certificates have validAfter and validUntil dates that
					are not expired.
					* The certified key in the ID certificate was used to sign both
					certificates.
					* The link certificate is correctly signed with the key in the
					ID certificate
					* The ID certificate is correctly self-signed.
				*/

				if (!this->certRsa1024Identity->IsValid() ||
					!this->certLinkKey->IsValid( *this->certRsa1024Identity.get() ) ||
					(this->certRsa1024AuthenticateCell != nullptr && !this->certRsa1024AuthenticateCell->IsValid( *this->certRsa1024Identity.get() ))
					) 
				{
					Serial.println("[DEBUG] Relay has invalid or expired X.509 certificates.");
					return false;
				}
		
				/*	The certified key in the ID certificate is a 1024-bit RSA key. */
				unsigned short keyLen = this->certRsa1024Identity->GetRsaKeyLength();
				if (keyLen != 1024) {
					if (DEBUG) Serial.printf("[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", keyLen);
					return false;
				}

				/* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection. */

				// 
				// TODO
				//

				if (DEBUG) Serial.println("[DEBUG] Relay with RSA identity key only has the right and valid certificates.");

				return true;
			}
			else {
				if (DEBUG) Serial.println("[DEBUG] Relay has no valid certificates to verify (no identity)!");
				return false;
			}

			/*
				In both cases above, checking these conditions is sufficient to
				authenticate that the initiator is talking to the Tor node with the
				expected identity, as certified in the ID certificate(s).
			*/
		}
	
		/**
		 * Method (only if debug active) print all short info of certificates, order of CertType
		*/
		void PrintAllCertificateShortInfo() {
			if (DEBUG) {
				if (this->certLinkKey != nullptr) this->certLinkKey->PrintCertInfo();
				if (this->certRsa1024Identity != nullptr) this->certRsa1024Identity->PrintCertInfo();
				if (this->certRsa1024AuthenticateCell != nullptr) this->certRsa1024AuthenticateCell->PrintCertInfo();
				if (this->certEd25519SigningKey != nullptr) this->certEd25519SigningKey->PrintCertInfo();
				if (this->certTLSLink != nullptr) this->certTLSLink->PrintCertInfo();
				if (this->certEd25519AuthenticateCellLink != nullptr) this->certEd25519AuthenticateCellLink->PrintCertInfo();
				if (this->certRSAEd25519CrossCertificate != nullptr) this->certRSAEd25519CrossCertificate->PrintCertInfo();
				
			}
		}
	};

	/**
	 * This class contains methods to query for a suitable relay.
	 * Actually any request for relay is done via Onionoo service because downloading consensus list from
	 * authorities requires (April 2021) ~2MB space and ESP has poor. In futures more relays will be added
	 * and this will bring to much more space required.
	*/
	class BriandTorRelaySearcher {
		protected:

		unsigned char skipRandomResults;
		unsigned char limitRandom;
		unsigned char randomPick;

		/**
		 * Method to set random members
		*/
		void randomize() {
			// Doing an Onionoo query could drive on data leak by MITM
			// Asking just a single relay that matches leds to "I know you are using node XX in your circuit path"
			// Doing N queries to have a minor probability leds to delays.
			// Also I see that Onionoo responses with almost the same relays for the same request.
			// Solution adopted is to ask for a bunch of limitRandom relays and choose a random one.
			// Skipping first skipRandomResults should help to get always different results

			// Always skip at least 1
			this->skipRandomResults = Briand::BriandUtils::GetRandomByte() + 1;

			this->limitRandom = 0;
			// Limit to max 5 result to save RAM!! Never ask for just 1!
			while (this->limitRandom <= 1)
				this->limitRandom = ( Briand::BriandUtils::GetRandomByte() % 5 ) + 1;

			// Random pick one from the list
			this->randomPick = ( Briand::BriandUtils::GetRandomByte() % this->limitRandom );
		}

		/**
		 * Method to query Onionoo service.
		 * @param type "relay" or "bridge"
		 * @param fields comma-separated fields to retrieve
		 * @param flagMask mask of required flags
		 * @param success bool to indicate if the call was sucessful
		 * @return ArduinoJson's DynamicJsonDocument if success, pre-filtered
		*/
		DynamicJsonDocument GetOnionooJson(const string& type, const string& fields, const unsigned short& flagsMask, bool& success) {
			// Randomize for subsequent method invoke
			this->randomize();

			short httpCode = 0;
			string randomAgent = string( Briand::BriandUtils::GetRandomHostName().get() );

			// Success to false
			success = false;

			ostringstream urlBuilder("");
			// Main URL
			urlBuilder << "/details?search=";
			// Search by flags
			// WARNING: clientHttp DO NOT urlencode! So %20 instead of space must be provided!
			urlBuilder << Briand::BriandUtils::BriandTorRelayFlagsToString(flagsMask, "flag:", "%20");
			// Just relays
			urlBuilder << "&type=" << type;
			// Take just needed fields
			urlBuilder << "&fields=" << fields;
			// Must be a running relay
			urlBuilder << "&running=true";
			// Must run recommended version
			urlBuilder << "&recommended_version=true";
			// Skip top N results in order to choose a different one
			urlBuilder << "&offset=" << static_cast<unsigned short>( this->skipRandomResults );
			// Take a random number bunch
			urlBuilder << "&limit=" << static_cast<unsigned short>( this->limitRandom );

			DynamicJsonDocument doc = Briand::BriandNet::HttpsGetJson(
				"onionoo.torproject.org", 443,
				urlBuilder.str(),
				httpCode, success, randomAgent,
				2048
			);

			if (!success) {
				Serial.printf("[ERR] Error on downloading Onionoo relay. Http code: %d Deserialization success: %d\n", httpCode, success);
			}

			return doc;
		}

		public:

		BriandTorRelaySearcher() {
			this->randomize();
		}

		~BriandTorRelaySearcher() {
		}

		//
		// TODO: get a significative bunch of nodes (>=100) for each type
		// save to a file and then use it randomly
		//

		/**
		 * Search for Guard node
		 * @return A unique pointer to BriandTorRelay object if success, nullptr if fails.
		*/
		unique_ptr<Briand::BriandTorRelay> GetGuardRelay() {
			// Perform request
			bool foundSuccess = false;
			auto found = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_GUARD_MUST_HAVE, foundSuccess);

			if (foundSuccess) {
				auto relay = make_unique<Briand::BriandTorRelay>();
				relay->nickname->assign( found["relays"][this->randomPick]["nickname"].as<const char*>() );
				relay->fingerprint->assign( found["relays"][this->randomPick]["fingerprint"].as<const char*>() );
				relay->first_address->assign( found["relays"][this->randomPick]["or_addresses"][0].as<const char*>() );

				found.clear(); // empty & free

				if (DEBUG) Serial.printf("[DEBUG] Got GUARD relay: %s %s %s\n", relay->nickname->c_str(), relay->first_address->c_str(), relay->fingerprint->c_str());

				return std::move(relay);
			}

			return nullptr;
		}

		/**
		 * Search for Middle node
		 * @return A unique pointer to BriandTorRelay object if success, nullptr if fails.
		*/
		unique_ptr<Briand::BriandTorRelay> GetMiddleRelay() {
			// Perform request
			bool foundSuccess = false;
			auto found = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_MIDDLE_MUST_HAVE, foundSuccess);

			if (foundSuccess) {
				auto relay = make_unique<Briand::BriandTorRelay>();
				relay->nickname->assign( found["relays"][this->randomPick]["nickname"].as<const char*>() );
				relay->fingerprint->assign( found["relays"][this->randomPick]["fingerprint"].as<const char*>() );
				relay->first_address->assign( found["relays"][this->randomPick]["or_addresses"][0].as<const char*>() );

				found.clear(); // empty & free

				if (DEBUG) Serial.printf("[DEBUG] Got MIDDLE relay: %s %s %s\n", relay->nickname->c_str(), relay->first_address->c_str(), relay->fingerprint->c_str());

				return std::move(relay);
			}

			return nullptr;
		}

		/**
		 * Search for Exit node
		 * @return A unique pointer to BriandTorRelay object if success, nullptr if fails.
		*/
		unique_ptr<Briand::BriandTorRelay> GetExitRelay() {
			// Perform request
			bool foundSuccess = false;
			auto found = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_EXIT_MUST_HAVE, foundSuccess);

			if (foundSuccess) {
				auto relay = make_unique<Briand::BriandTorRelay>();
				relay->nickname->assign( found["relays"][this->randomPick]["nickname"].as<const char*>() );
				relay->fingerprint->assign( found["relays"][this->randomPick]["fingerprint"].as<const char*>() );
				relay->first_address->assign( found["relays"][this->randomPick]["or_addresses"][0].as<const char*>() );

				found.clear(); // empty & free

				if (DEBUG) Serial.printf("[DEBUG] Got EXIT relay: %s %s %s\n", relay->nickname->c_str(), relay->first_address->c_str(), relay->fingerprint->c_str());

				return std::move(relay);
			}

			return nullptr;
		}
	};
}