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

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

#include <iostream>
#include <memory>
#include <sstream>

#include <ArduinoJson.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand {
	/**
	 * This class describes and keeps information about a single Tor Relay
	*/
	class BriandTorRelay {
		public:

		unique_ptr<string> nickname;
		unique_ptr<string> first_address;
		unique_ptr<string> fingerprint;
		unsigned short flags;

		// TODO: handle more fields (minimum necessary!)

		BriandTorRelay() {
			nickname = make_unique<string>("");
			first_address = make_unique<string>("");
			fingerprint = make_unique<string>("");
			flags = 0x0000;
		}

		~BriandTorRelay() {
			nickname.reset();
			first_address.reset();
			fingerprint.reset();
		}

		string GetHost() {
			int sepPos = this->first_address->find(':');
			if (sepPos != std::string::npos) {
				return string( this->first_address->substr(0, sepPos) );
			}
			else
				return string("");
		}

		unsigned short GetPort() {
			int sepPos = this->first_address->find(':');
			if (sepPos != std::string::npos) {
				return stoi( this->first_address->substr(sepPos + 1, this->first_address->length() ) );
			}
			else
				return 0;
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

			// Success to false
			success = false;

			// TODO: find a method to query https without give the CA root certificate hard-coded
			// maybe download it ?
			// Connection is still encrypted but there is no way to verify the server is the right one!

			auto clientHttp = make_unique<HTTPClient>();
			DynamicJsonDocument doc(2048); // Should be enough for data and safe for RAM...

			ostringstream urlBuilder("");
			// Main URL
			urlBuilder << "https://onionoo.torproject.org/details?search=";
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

			if (DEBUG) Serial.printf("[DEBUG] Relay request url: %s\n", urlBuilder.str().c_str());

			// Not providing a CACert will be a leak of security but hard-coding has disadvantages...	
			clientHttp->begin( urlBuilder.str().c_str() );
			int httpCode = clientHttp->GET();

			if (httpCode == 200) {
				// It is safe RAM beacause request just little data with poor fields,
				// thus RAM should be fine...
								
				string responseContent = string( clientHttp->getString().c_str() );
				clientHttp->end();
				clientHttp.reset(); // now please, I need RAM!

				if (DEBUG) Serial.printf("[DEBUG] Got response HTTP/200\n");
				if (DEBUG) Serial.printf("[DEBUG] Raw response of %d bytes: %s\n", responseContent.length(), responseContent.c_str() );

				StaticJsonDocument<200> filter; // used to filter just what needed!
				filter["relays_published"] = true;
				filter["relays"][0]["nickname"] = true;
				filter["relays"][0]["fingerprint"] = true;
				filter["relays"][0]["or_addresses"] = true;

				DeserializationError err = deserializeJson(doc, responseContent.c_str(), DeserializationOption::Filter(filter));
				
				if (err) {
					Serial.printf("[ERR] Error on deserialization from Onionoo!\n");
				}
				else {
					if (DEBUG) Serial.printf("[DEBUG] Json document allocated %d bytes\n", doc.memoryUsage());
					doc.shrinkToFit();
					if (DEBUG) Serial.printf("[DEBUG] Json document shrink to %d bytes.\n", doc.memoryUsage());

					// Success!
					success = true;
				}
			}
			else
				Serial.printf("[ERR] Error on downloading Onionoo relay. Http code: %d\n", httpCode);
			
			return doc;
		}

		public:

		BriandTorRelaySearcher() {
			this->randomize();
		}

		~BriandTorRelaySearcher() {
		}

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