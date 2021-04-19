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
#include "BriandTorCertificate.hxx"

using namespace std;

namespace Briand {
	/**
	 * This class describes and keeps information about a single Tor Relay
	*/
	class BriandTorRelay {
		private:
		
		/**
		 * Returns a certificate if match found, this->certificates->end() instead
		 * @return pointer to certificate 
		*/
		std::vector<Briand::BriandTorCertificate>::iterator FindCertByType(Briand::BriandTorCertificate::CertType type) {
			auto ptr = std::find_if(this->certificates->begin(), this->certificates->end(), [&type](const Briand::BriandTorCertificate& item) {return item.Type == type; } );
			return ptr;
		}

		public:

		unique_ptr<string> nickname;
		unique_ptr<string> first_address;
		unique_ptr<string> fingerprint;
		unsigned short flags;

		/** Contains CERTS cell certificates */
		unique_ptr<vector<Briand::BriandTorCertificate>> certificates;

		// TODO: handle more fields (minimum necessary if needed!)

		// Relay Certificates (ready after a CERTS cell is sent)
		
		BriandTorRelay() {
			nickname = make_unique<string>("");
			first_address = make_unique<string>("");
			fingerprint = make_unique<string>("");
			flags = 0x0000;
			certificates = make_unique<vector<Briand::BriandTorCertificate>>();
		}

		~BriandTorRelay() {
			nickname.reset();
			first_address.reset();
			fingerprint.reset();
			certificates.reset();
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
	
		/**
		 * Method validates certificates as required in Tor handshake protocol.
		 * @return true if all valid, false if not.
		*/
		bool ValidateCertificates() {
			if (this->certificates->size() == 0)
				return false;
			
			/*			
				To authenticate the responder as having a given Ed25519,RSA identity key
				combination, the initiator MUST check the following.

				[ see testCondition1 ]

				To authenticate the responder as having a given RSA identity only,
				the initiator MUST check the following:

				[see testCondition2]
			*/

			bool testCondition1 = ( this->FindCertByType(BriandTorCertificate::CertType::Ed25519_Identity) != this->certificates->end() ) &&
							 	  ( this->FindCertByType(BriandTorCertificate::CertType::RSA1024_Identity_Self_Signed) != this->certificates->end() );
			
			bool condition1Satisfied = false;

			bool testCondition2 = ( this->FindCertByType(BriandTorCertificate::CertType::RSA1024_Identity_Self_Signed) != this->certificates->end() );

			bool condition2Satisfied = false;
			
			if (testCondition1) {
				if (DEBUG) Serial.println("[DEBUG] Relay has Ed25519+RSA identity keys.");
				/*
					the initiator MUST check the following.

					* The CERTS cell contains exactly one CertType 2 "ID" certificate.
					* The CERTS cell contains exactly one CertType 4 Ed25519 "Id->Signing" cert.
					* The CERTS cell contains exactly one CertType 5 Ed25519 "Signing->link" certificate.
					* The CERTS cell contains exactly one CertType 7 "RSA->Ed25519" cross-certificate.
				*/

				unsigned short test;
				test = std::count_if(this->certificates->begin(), this->certificates->end(), [] (const BriandTorCertificate& x) { return x.Type == BriandTorCertificate::CertType::RSA1024_Identity_Self_Signed; });
				if (test != 1) {
					if (DEBUG) Serial.printf("[DEBUG] Error, found %d certificates of type 2, expected exactly one.\n", test);
					return false;
				}
				test = std::count_if(this->certificates->begin(), this->certificates->end(), [] (const BriandTorCertificate& x) { return x.Type == BriandTorCertificate::CertType::Ed25519_Signing_Key; });
				if (test != 1) {
					if (DEBUG) Serial.printf("[DEBUG] Error, found %d certificates of type 4, expected exactly one.\n", test);
					return false;
				}
				test = std::count_if(this->certificates->begin(), this->certificates->end(), [] (const BriandTorCertificate& x) { return x.Type == BriandTorCertificate::CertType::TLS_Link; });
				if (test != 1) {
					if (DEBUG) Serial.printf("[DEBUG] Error, found %d certificates of type 5, expected exactly one.\n", test);
					return false;
				}
				test = std::count_if(this->certificates->begin(), this->certificates->end(), [] (const BriandTorCertificate& x) { return x.Type == BriandTorCertificate::CertType::Ed25519_Identity; });
				if (test != 1) {
					if (DEBUG) Serial.printf("[DEBUG] Error, found %d certificates of type 7, expected exactly one.\n", test);
					return false;
				}

				/*
					* All X.509 certificates above have validAfter and validUntil dates; no X.509 or Ed25519 certificates are expired.
					* All certificates are correctly signed.
				*/

				auto ptrCa = this->FindCertByType(BriandTorCertificate::CertType::RSA1024_Identity_Self_Signed);
				auto ptrPeer = this->FindCertByType(BriandTorCertificate::CertType::LinkKeyWithRSA1024);

				if (ptrPeer == this->certificates->end()) {
					if (DEBUG) Serial.println("[DEBUG] Error, LinkKeyWithRSA1024 not found!");
					return false;
				}

				if (!ptrPeer->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, LinkKeyWithRSA1024 is invalid!");
					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] LinkKeyWithRSA1024 certificate validation: successs.");

				/* The RSA ID certificate is correctly self-signed. */
				if (!ptrCa->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, RSA1024_Identity_Self_Signed is invalid!");
					return false;
				}

				/* The certified key in the ID certificate is a 1024-bit RSA key. */
				if (ptrCa->GetRsaKeyLength() != 1024) {
					unsigned int ks = ptrCa->GetRsaKeyLength();
					if (DEBUG) Serial.printf("[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", ks);
					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] RSA1024_Identity_Self_Signed certificate validation: successs.");

				if (DEBUG) Serial.println("[DEBUG] X.509 certificates OK, starting verification of Ed25519 certificates.");

				// TEST ED25519 CERTIFICATES
				
				// TODO : REAL CA!!!!

				ptrPeer = this->FindCertByType(BriandTorCertificate::CertType::Ed25519_Signing_Key);

				if (!ptrPeer->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, Ed25519_Signing_Key is not valid.");
					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] Ed25519_Signing_Key certificate validation: successs.");

				ptrPeer = this->FindCertByType(BriandTorCertificate::CertType::TLS_Link);
				if (!ptrPeer->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, TLS_Link is not valid.");
					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] TLS_Link certificate validation: successs.");

				ptrPeer = this->FindCertByType(BriandTorCertificate::CertType::Ed25519_Identity);
				if (!ptrPeer->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, Ed25519_Identity is not valid.");
					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] Ed25519_Identity certificate validation: successs.");

				// --------------------------

				//
				// TODO
				//

				/*
					* The certified key in the Signing->Link certificate matches the SHA256 digest of the certificate that was used to authenticate the TLS connection.
					* The identity key listed in the ID->Signing cert was used to sign the ID->Signing Cert.
					* The Signing->Link cert was signed with the Signing key listed in the ID->Signing cert.
					* The RSA->Ed25519 cross-certificate certifies the Ed25519 identity, and is signed with the RSA identity listed in the "ID" certificate.
					
					* 
				*/

				if (DEBUG) Serial.println("[DEBUG] Ed25519 certificates OK.");
			}
			else if (testCondition2) {
				if (DEBUG) Serial.println("[DEBUG] Relay has RSA identity key only.");
				
				/*
					the initiator MUST check the following.

					* The CERTS cell contains exactly one CertType 1 "Link" certificate.
					* The CERTS cell contains exactly one CertType 2 "ID" certificate.
				*/

				unsigned short test;
				test = std::count_if(this->certificates->begin(), this->certificates->end(), [] (const BriandTorCertificate& x) { return x.Type == BriandTorCertificate::CertType::LinkKeyWithRSA1024; });
				if (test != 1) {
					if (DEBUG) Serial.printf("[DEBUG] Error, found %d certificates of type 1, expected exactly one.\n", test);
					return false;
				}
				test = std::count_if(this->certificates->begin(), this->certificates->end(), [] (const BriandTorCertificate& x) { return x.Type == BriandTorCertificate::CertType::RSA1024_Identity_Self_Signed; });
				if (test != 1) {
					if (DEBUG) Serial.printf("[DEBUG] Error, found %d certificates of type 2, expected exactly one.\n", test);
					return false;
				}

				/*
					* Both certificates have validAfter and validUntil dates that are not expired.
					* The link certificate is correctly signed with the key in the ID certificate
					* The certified key in the ID certificate was used to sign both certificates.
				*/

				auto ptrCa = this->FindCertByType(BriandTorCertificate::CertType::RSA1024_Identity_Self_Signed);
				auto ptrPeer = this->FindCertByType(BriandTorCertificate::CertType::LinkKeyWithRSA1024);

				if (ptrPeer == this->certificates->end()) {
					if (DEBUG) Serial.println("[DEBUG] Error, LinkKeyWithRSA1024 not found!");
					return false;
				}

				if (!ptrPeer->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, LinkKeyWithRSA1024 is invalid!");
					return false;
				}

				if (DEBUG) Serial.println("[DEBUG] LinkKeyWithRSA1024 certificate validation: successs.");

				/* The ID certificate is correctly self-signed. */
				if (!ptrCa->isValid( *ptrCa )) {
					if (DEBUG) Serial.println("[DEBUG] Error, RSA1024_Identity_Self_Signed is invalid!");
					return false;
				}

				/* The certified key in the ID certificate is a 1024-bit RSA key. */
				if (ptrCa->GetRsaKeyLength() != 1024) {
					unsigned int ks = ptrCa->GetRsaKeyLength();
					if (DEBUG) Serial.printf("[DEBUG] Error, RSA1024_Identity_Self_Signed has an invalid key size of %d bit, expected 1024.\n", ks);
					return false;
				}

				/*
					* The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection.
				*/

				//
				// TODO
				//

				if (DEBUG) Serial.println("[DEBUG] RSA1024_Identity_Self_Signed certificate validation: successs.");
				if (DEBUG) Serial.println("[DEBUG] X.509 certificates OK");
			}
			else  {
				if (DEBUG) Serial.println("[DEBUG] Error, relay has no identity keys.");
				return false;
			}

			/*
				In both cases above, checking these conditions is sufficient to
				authenticate that the initiator is talking to the Tor node with the
				expected identity, as certified in the ID certificate(s).
			*/

			// DEBUG !!!!!!!!
			return true;

			return condition1Satisfied || condition2Satisfied;
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