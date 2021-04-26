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

#include <Arduino.h> /* MUST BE THE FIRST HEADER IN CPP FILES! */

#include "BriandTorRelaySearcher.hxx"

#include <iostream>
#include <memory>
#include <sstream>
#include <vector>
#include <algorithm>

#include <ArduinoJson.h>
#include <FS.h>
#include <SPIFFS.h>
#include <WiFiClientSecure.h>

// Crypto library chosen
#include <mbedtls/ecdh.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorCertificates.hxx"
#include "BriandTorRelay.hxx"

namespace Briand {

	void BriandTorRelaySearcher::randomize() {
		// Doing an Onionoo query could drive on data leak by MITM
		// Asking just a single relay that matches leds to "I know you are using node XX in your circuit path"
		// Doing N queries to have a minor probability leds to delays.
		// Also I see that Onionoo responses with almost the same relays for the same request.
		// Solution adopted is to ask for a bunch of limitRandom relays and choose a random one.
		// Skipping first skipRandomResults should help to get always different results

		// Implementation reviewed with a spiffs cache of N nodes.

		// Always skip at least 1
		this->skipRandomResults = Briand::BriandUtils::GetRandomByte() + 1;

		// Random picking for the array (see method GetGuard etc.)
		this->randomPick = BriandUtils::GetRandomByte() % TOR_NODES_CACHE_SIZE;

		/* DELTED old implementation
		this->limitRandom = 0;

		// Limit to max 5 result to save RAM!! Never ask for just 1!
		while (this->limitRandom <= 1)
			this->limitRandom = ( Briand::BriandUtils::GetRandomByte() % 5 ) + 1;
		
		// Random pick one from the list
		//this->randomPick = ( Briand::BriandUtils::GetRandomByte() % this->limitRandom );
		
		*/
	}

	unique_ptr<string> BriandTorRelaySearcher::GetOnionooJson(const string& type, const string& fields, const unsigned short& flagsMask, bool& success, const unsigned short overrideLimit /* = 0*/) {
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

		if (overrideLimit != 0) {
			urlBuilder << "&limit=" << overrideLimit;
		}
		else {
			// Use the setting
			urlBuilder << "&limit=" << static_cast<unsigned short>( TOR_NODES_CACHE_SIZE );
		}

		auto response = BriandNet::HttpsGet(
			"onionoo.torproject.org", 443,
			urlBuilder.str(),
			httpCode, randomAgent,
			false	// CHANGED TO FALSE, seems that Onionoo service returns extra \r\n that would truncate response!! OMG
		);

		if (httpCode != 200) {
			if (VERBOSE) Serial.printf("[ERR] Error on downloading Onionoo relay. Http code: %d\n", httpCode);
		}
		else {
			if (DEBUG) Serial.printf("[DEBUG] Response before trimming has size %d bytes\n", response->length());

			// Seems that sometimes additional bytes are included in response when body only is requested. 
			// So remove before the first { and after the last }

			auto fpos = response->find("{");
			auto lpos = response->find_last_of("}");

			if (fpos != std::string::npos) response->erase(response->begin(), response->begin() + fpos);
			if (lpos != std::string::npos) response->erase(response->begin() + lpos + 1, response->end());

			// Remove all occourences of the \r\n to minify space needed!
			BriandUtils::StringTrimAll(*response.get(), '\r');
			BriandUtils::StringTrimAll(*response.get(), '\n');

			if (DEBUG) Serial.printf("[DEBUG] After trimming has size %d bytes\n", response->length());

			success = true;
		}

		return std::move(response);
	}

	void BriandTorRelaySearcher::RefreshOnionooCache(const short maxTentatives) {
		/*
			CACHE FILE FORMAT:
			Json file contaning downloaded Onionoo informations PLUS a header field called
			"cachecreatedon":00000000
			it contains the timestamp of the last download. If this timestamp is older
			than TOR_NODES_CACHE_VAL_H than cache must be considered invalid.
		*/

		this->cacheValid = false;

		bool success;
		short tentative;

		// Start with guard cache
		success = false;
		tentative = 0;
		while (!success && tentative < maxTentatives) {
			if (DEBUG) Serial.printf("[DEBUG] Downloading guard cache from Oniooo, tentative %d of %d.\n", tentative+1, maxTentatives);
			// effective_family and exit_policy_summary removed due to too much bytes...
			auto json = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_GUARD_MUST_HAVE, success, TOR_NODES_CACHE_SIZE);
			if (success) {
				if (DEBUG) Serial.printf("[DEBUG] Downloading guard cache from Oniooo success, saving cache.\n");
				// Prepend the time to object (the first byte is the "{" initialization)
				string addTimestamp = "\"cachecreatedon\":" + std::to_string(BriandUtils::GetUnixTime()) + ",";
				json->insert(json->begin()+1, addTimestamp.begin(), addTimestamp.end());
				if (DEBUG) Serial.printf("[DEBUG] Guard cache from Oniooo will have a size of %u bytes.\n", json->size());
				File f = SPIFFS.open(NODES_FILE_GUARD, "w");
				// Buffer has important size, so is better write with buffers of 1K bytes
				while(json->length() > 0) {
					if (json->length() < 1000) {
						f.write(reinterpret_cast<const unsigned char*>(json->c_str()), json->length());
						json->clear();
					}
					else {
						f.write(reinterpret_cast<const unsigned char*>(json->c_str()), 1000);
						json->erase(json->begin(), json->begin()+1000);
					}
				}
				f.close();
				json.reset(); // save ram
				if (DEBUG) Serial.printf("[DEBUG] Guard cache from Oniooo saved to %s\n", this->NODES_FILE_GUARD);
			}

			tentative++;
		}

		if (tentative == maxTentatives) {
			if (DEBUG) Serial.println("[DEBUG] RefreshOnionooCache permanent failure. exiting.");
			return;
		}

		// Proceed with middle
		success = false;
		tentative = 0;
		while (!success && tentative < maxTentatives) {
			if (DEBUG) Serial.printf("[DEBUG] Downloading middle cache from Oniooo, tentative %d of %d.\n", tentative+1, maxTentatives);
			// effective_family and exit_policy_summary removed due to too much bytes...			
			auto json = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_MIDDLE_MUST_HAVE, success, TOR_NODES_CACHE_SIZE);
			if (success) {
				if (DEBUG) Serial.printf("[DEBUG] Downloading middle cache from Oniooo success, saving cache.\n");
				// Prepend the time to object (the first byte is the "{" initialization)
				string addTimestamp = "\"cachecreatedon\":" + std::to_string(BriandUtils::GetUnixTime()) + ",";
				json->insert(json->begin()+1, addTimestamp.begin(), addTimestamp.end());
				if (DEBUG) Serial.printf("[DEBUG] Middle cache from Oniooo will have a size of %u bytes.\n", json->size());
				File f = SPIFFS.open(NODES_FILE_MIDDLE, "w");
				// Buffer has important size, so is better write with buffers of 1K bytes
				while(json->length() > 0) {
					if (json->length() < 1000) {
						f.write(reinterpret_cast<const unsigned char*>(json->c_str()), json->length());
						json->clear();
					}
					else {
						f.write(reinterpret_cast<const unsigned char*>(json->c_str()), 1000);
						json->erase(json->begin(), json->begin()+1000);
					}
				}
				f.close();
				json.reset(); // save ram
				if (DEBUG) Serial.printf("[DEBUG] Middle cache from Oniooo saved to %s\n", this->NODES_FILE_MIDDLE);
			}

			tentative++;
		}

		if (tentative == maxTentatives) {
			if (DEBUG) Serial.println("[DEBUG] RefreshOnionooCache permanent failure. exiting.");
			return;
		}

		// Finish with exits
		success = false;
		tentative = 0;
		while (!success && tentative < maxTentatives) {
			if (DEBUG) Serial.printf("[DEBUG] Downloading exit cache from Oniooo, tentative %d of %d.\n", tentative+1, maxTentatives);
			// Exit nodes => require exit_summary!
			// effective_family and exit_policy_summary removed due to too much bytes...
			auto json = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_EXIT_MUST_HAVE, success, TOR_NODES_CACHE_SIZE);
			if (success) {
				if (DEBUG) Serial.printf("[DEBUG] Downloading exit cache from Oniooo success, saving cache.\n");
				// Prepend the time to object (the first byte is the "{" initialization)
				string addTimestamp = "\"cachecreatedon\":" + std::to_string(BriandUtils::GetUnixTime()) + ",";
				json->insert(json->begin()+1, addTimestamp.begin(), addTimestamp.end());
				if (DEBUG) Serial.printf("[DEBUG] Middle exit from Oniooo will have a size of %u bytes.\n", json->size());
				File f = SPIFFS.open(NODES_FILE_EXIT, "w");
				// Buffer has important size, so is better write with buffers of 1K bytes
				while(json->length() > 0) {
					if (json->length() < 1000) {
						f.write(reinterpret_cast<const unsigned char*>(json->c_str()), json->length());
						json->clear();
					}
					else {
						f.write(reinterpret_cast<const unsigned char*>(json->c_str()), 1000);
						json->erase(json->begin(), json->begin()+1000);
					}
				}
				f.close();
				json.reset(); // save ram
				if (DEBUG) Serial.printf("[DEBUG] Exit cache from Oniooo saved to %s\n", this->NODES_FILE_EXIT);
			}

			tentative++;
		}

		if (tentative == maxTentatives) {
			if (DEBUG) Serial.println("[DEBUG] RefreshOnionooCache permanent failure. exiting.");
			return;
		}

		// of course....
		this->cacheValid = true;
	}

	bool BriandTorRelaySearcher::CheckCacheFile(const char* filename) {
		bool valid = false;

		if (SPIFFS.exists(filename)) {
			DynamicJsonDocument doc(this->EXPECTED_SIZE);

			File file = SPIFFS.open(filename, "r");
			DeserializationError err = deserializeJson(doc, file);
			if (!err) {
				unsigned long int cacheAge = doc["cachecreatedon"];//.as<unsigned long int>();
				if (DEBUG) Serial.printf("[DEBUG] %s cache created on %lu.\n", filename, cacheAge);
				if ( (cacheAge + (TOR_NODES_CACHE_VAL_H*3600)) >= BriandUtils::GetUnixTime() ) {
					valid = true;
				}
			}
			else {
				if (DEBUG) Serial.printf("[DEBUG] %s cache deserialization error: %s\n", filename, err.c_str());
			}

			file.close();
		}
		else {
			if (DEBUG) Serial.printf("[DEBUG] %s cache file does not exist.\n", filename);
		}

		return valid;
	}

	bool BriandTorRelaySearcher::IPsInSameFamily(const string& first, const string& second) {
		IPAddress ip1, ip2;
		ip1.fromString(first.substr(0, first.find_first_of(":")).c_str());
		ip2.fromString(second.substr(0, second.find_first_of(":")).c_str());
		return (ip1[0] == ip2[0] && ip1[1] == ip2[1]);
	}

	BriandTorRelaySearcher::BriandTorRelaySearcher() {
		this->randomize();

		// Check for cache validity
		this->cacheValid = 
			this->CheckCacheFile(this->NODES_FILE_GUARD) && 
			this->CheckCacheFile(this->NODES_FILE_MIDDLE) &&
			this->CheckCacheFile(this->NODES_FILE_EXIT);

		// Do not update cache there, will be done when requesting first node if needed.
	}

	BriandTorRelaySearcher::~BriandTorRelaySearcher() {
	}

	unique_ptr<BriandTorRelay> BriandTorRelaySearcher::GetGuardRelay() {
		unique_ptr<BriandTorRelay> relay = nullptr;

		if (!this->cacheValid) {
			if (DEBUG) Serial.println("[DEBUG] Nodes cache invalid, download and rebuilding.");
			RefreshOnionooCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			if (DEBUG) Serial.printf("[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			DynamicJsonDocument json(this->EXPECTED_SIZE);

			File file = SPIFFS.open(this->NODES_FILE_GUARD, "r");
			DeserializationError err = deserializeJson(json, file);
			if (!err) {
				relay = make_unique<Briand::BriandTorRelay>();

				// Sure you have enough?
				while (json["relays"][this->randomPick].isNull())
					this->randomize();

				relay->nickname->assign( json["relays"][this->randomPick]["nickname"].as<const char*>() );
				relay->fingerprint->assign( json["relays"][this->randomPick]["fingerprint"].as<const char*>() );
				relay->first_address->assign( json["relays"][this->randomPick]["or_addresses"][0].as<const char*>() );

				if (json["relays"][this->randomPick].containsKey("effective_family"))
					relay->effective_family->assign( json["relays"][this->randomPick]["effective_family"].as<const char*>() );

				json.clear();
			}
			else {
				if (DEBUG) Serial.printf("[DEBUG] %s cache deserialization error: %s. Cache has been invalidated.\n", this->NODES_FILE_GUARD, err.c_str());
				this->cacheValid = false;
			}

			file.close();
		}
		else {
			if (VERBOSE) Serial.println("[DEBUG] Invalid cache at second tentative. Skipping with failure.");
		}

		return relay;
	}

	unique_ptr<BriandTorRelay> BriandTorRelaySearcher::GetMiddleRelay(const string& avoidGuardIp) {
		unique_ptr<BriandTorRelay> relay = nullptr;

		if (!this->cacheValid) {
			if (DEBUG) Serial.println("[DEBUG] Nodes cache invalid, download and rebuilding.");
			RefreshOnionooCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			if (DEBUG) Serial.printf("[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			DynamicJsonDocument json(this->EXPECTED_SIZE);

			File file = SPIFFS.open(this->NODES_FILE_MIDDLE, "r");
			DeserializationError err = deserializeJson(json, file);
			if (!err) {
				relay = make_unique<Briand::BriandTorRelay>();

				// Sure you have enough?
				while (json["relays"][this->randomPick].isNull())
					this->randomize();

				// Check that the IP do not match if parameter given
				if (avoidGuardIp.length() > 0) {
					// Use it in the rare case the cache contains all-same-family nodes
					auto allViewedCheck = make_unique<vector<unsigned char>>();
					bool sameFamily;
					do {
						sameFamily = this->IPsInSameFamily( string(json["relays"][this->randomPick]["or_addresses"][0].as<const char*>()), avoidGuardIp);

						if (sameFamily) {
							allViewedCheck->push_back(this->randomPick);
							this->randomize();
							// Sure you have enough?
							while (json["relays"][this->randomPick].isNull())
								this->randomize();
						}
					} while (sameFamily || allViewedCheck->size() == TOR_NODES_CACHE_SIZE);

					if (sameFamily && allViewedCheck->size() == TOR_NODES_CACHE_SIZE) {
						if (VERBOSE) Serial.println("[ERR] The middle tor cache has nodes that always matches the selected guard... FAILURE!");
						return relay;
					}
					else {
						if (DEBUG) Serial.printf("[DEBUG] Found that middle IP %s is different than guard %s and it is OK.\n", json["relays"][this->randomPick]["or_addresses"][0].as<const char*>(), avoidGuardIp.c_str());
					}
				}

				relay->nickname->assign( json["relays"][this->randomPick]["nickname"].as<const char*>() );
				relay->fingerprint->assign( json["relays"][this->randomPick]["fingerprint"].as<const char*>() );
				relay->first_address->assign( json["relays"][this->randomPick]["or_addresses"][0].as<const char*>() );

				if (json["relays"][this->randomPick].containsKey("effective_family"))
					relay->effective_family->assign( json["relays"][this->randomPick]["effective_family"].as<const char*>() );

				json.clear();
			}
			else {
				if (DEBUG) Serial.printf("[DEBUG] %s cache deserialization error: %s. Cache has been invalidated.\n", this->NODES_FILE_MIDDLE, err.c_str());
				this->cacheValid = false;
			}

			file.close();
		}
		else {
			if (VERBOSE) Serial.println("[DEBUG] Invalid cache at second tentative. Skipping with failure.");
		}

		return relay;
	}

	unique_ptr<BriandTorRelay> BriandTorRelaySearcher::GetExitRelay(const string& avoidGuardIp, const string& avoidMiddleIp) {
		unique_ptr<BriandTorRelay> relay = nullptr;

		if (!this->cacheValid) {
			if (DEBUG) Serial.println("[DEBUG] Nodes cache invalid, download and rebuilding.");
			RefreshOnionooCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			if (DEBUG) Serial.printf("[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			DynamicJsonDocument json(this->EXPECTED_SIZE);

			File file = SPIFFS.open(this->NODES_FILE_EXIT, "r");
			DeserializationError err = deserializeJson(json, file);
			if (!err) {
				relay = make_unique<Briand::BriandTorRelay>();

				// Sure you have enough?
				while (json["relays"][this->randomPick].isNull())
					this->randomize();

				// Check that the IP do not match if parameter given
				if (avoidGuardIp.length() > 0 && avoidMiddleIp.length() > 0) {
					// Use it in the rare case the cache contains all-same-family nodes
					auto allViewedCheck = make_unique<vector<unsigned char>>();
					bool sameFamily;
					do {
						sameFamily = this->IPsInSameFamily( string(json["relays"][this->randomPick]["or_addresses"][0].as<const char*>()), avoidGuardIp) ||
										this->IPsInSameFamily( string(json["relays"][this->randomPick]["or_addresses"][0].as<const char*>()), avoidMiddleIp);

						if (sameFamily) {
							allViewedCheck->push_back(this->randomPick);
							this->randomize();
							// Sure you have enough?
							while (json["relays"][this->randomPick].isNull())
								this->randomize();
						}
					} while (sameFamily && allViewedCheck->size() < TOR_NODES_CACHE_SIZE);

					if (sameFamily && allViewedCheck->size() == TOR_NODES_CACHE_SIZE) {
						if (VERBOSE) Serial.println("[ERR] The exit tor cache has nodes that always matches the selected guard/middle... FAILURE!");
						return relay;
					}
					else {
						if (DEBUG) Serial.printf("[DEBUG] Found that exit IP %s is different than guard %s and middle %s and it is OK.\n", json["relays"][this->randomPick]["or_addresses"][0].as<const char*>(), avoidGuardIp.c_str(), avoidMiddleIp.c_str());
					}
				}
				else if ((avoidGuardIp.length() + avoidMiddleIp.length()) > 0) {
					if (VERBOSE) Serial.println("[WARNING] In GetExitRelay received only one (guard or middle) to avoid. CHECK WILL NOT BE DONE!");
				}

				relay->nickname->assign( json["relays"][this->randomPick]["nickname"].as<const char*>() );
				relay->fingerprint->assign( json["relays"][this->randomPick]["fingerprint"].as<const char*>() );
				relay->first_address->assign( json["relays"][this->randomPick]["or_addresses"][0].as<const char*>() );

				if (json["relays"][this->randomPick].containsKey("effective_family"))
					relay->effective_family->assign( json["relays"][this->randomPick]["effective_family"].as<const char*>() );

				json.clear();
			}
			else {
				if (DEBUG) Serial.printf("[DEBUG] %s cache deserialization error: %s. Cache has been invalidated.\n", this->NODES_FILE_EXIT, err.c_str());
				this->cacheValid = false;
			}

			file.close();
		}
		else {
			if (VERBOSE) Serial.println("[DEBUG] Invalid cache at second tentative. Skipping with failure.");
		}

		return relay;
	}

	void BriandTorRelaySearcher::InvalidateCache(bool forceRefresh) {
		if (SPIFFS.exists(this->NODES_FILE_GUARD)) SPIFFS.remove(this->NODES_FILE_GUARD);
		if (SPIFFS.exists(this->NODES_FILE_MIDDLE)) SPIFFS.remove(this->NODES_FILE_MIDDLE);
		if (SPIFFS.exists(this->NODES_FILE_EXIT)) SPIFFS.remove(this->NODES_FILE_EXIT);
		if (forceRefresh) this->RefreshOnionooCache();
	}

	void BriandTorRelaySearcher::PrintCacheContents() {
		if (DEBUG) {
			Serial.println("[DEBUG] GUARDS CACHE:");
			BriandUtils::PrintFileContent(this->NODES_FILE_GUARD);
			Serial.println("");
			Serial.println("[DEBUG] MIDDLE CACHE:");
			BriandUtils::PrintFileContent(this->NODES_FILE_MIDDLE);
			Serial.println("");
			Serial.println("[DEBUG] EXIT CACHE:");
			BriandUtils::PrintFileContent(this->NODES_FILE_EXIT);
			Serial.println("");
			Serial.printf("[DEBUG] Cache status is: %s\n", (this->cacheValid ? "Valid" : "Invalid"));
		}
	}
}