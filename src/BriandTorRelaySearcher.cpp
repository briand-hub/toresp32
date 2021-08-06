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

#include "BriandTorRelaySearcher.hxx"
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
			ESP_LOGW(LOGTAG, "[ERR] Error on downloading Onionoo relay. Http code: %d\n", httpCode);
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] Response before trimming has size %d bytes\n", response->length());

			// Seems that sometimes additional bytes are included in response when body only is requested. 
			// So remove before the first { and after the last }

			auto fpos = response->find("{");
			auto lpos = response->find_last_of("}");

			if (fpos != std::string::npos) response->erase(response->begin(), response->begin() + fpos);
			if (lpos != std::string::npos) response->erase(response->begin() + lpos + 1, response->end());

			// Remove all occourences of the \r\n to minify space needed!
			BriandUtils::StringTrimAll(*response.get(), '\r');
			BriandUtils::StringTrimAll(*response.get(), '\n');

			ESP_LOGD(LOGTAG, "[DEBUG] After trimming has size %d bytes\n", response->length());

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
			ESP_LOGD(LOGTAG, "[DEBUG] Downloading guard cache from Oniooo, tentative %d of %d.\n", tentative+1, maxTentatives);
			// effective_family and exit_policy_summary removed due to too much bytes...
			auto json = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_GUARD_MUST_HAVE, success, TOR_NODES_CACHE_SIZE);
			if (success) {
				ESP_LOGD(LOGTAG, "[DEBUG] Downloading guard cache from Oniooo success, saving cache.\n");
				
				// Prepend the time to object (the first byte is the "{" initialization)
				string addTimestamp = "\"cachecreatedon\":" + std::to_string(BriandUtils::GetUnixTime()) + ",";
				json->insert(json->begin()+1, addTimestamp.begin(), addTimestamp.end());
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache from Oniooo will have a size of %u bytes.\n", json->size());
				
				ofstream f(NODES_FILE_GUARD, ios::out | ios::trunc);

				// Buffer has important size, so is better write with buffers of 1K bytes
				while(json->length() > 0) {
					if (json->length() < 1000) {
						f << json->c_str();
						json->clear();
					}
					else {
						f.write(json->c_str(), 1000);
						json->erase(json->begin(), json->begin()+1000);
					}
				}

				f.flush();
				f.close();
				json.reset(); // save ram
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache from Oniooo saved to %s\n", this->NODES_FILE_GUARD);
			}

			tentative++;
		}

		if (tentative == maxTentatives) {
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshOnionooCache permanent failure. exiting.\n");
			return;
		}

		// Proceed with middle
		success = false;
		tentative = 0;
		while (!success && tentative < maxTentatives) {
			ESP_LOGD(LOGTAG, "[DEBUG] Downloading middle cache from Oniooo, tentative %d of %d.\n", tentative+1, maxTentatives);
			// effective_family and exit_policy_summary removed due to too much bytes...			
			auto json = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_MIDDLE_MUST_HAVE, success, TOR_NODES_CACHE_SIZE);
			if (success) {
				ESP_LOGD(LOGTAG, "[DEBUG] Downloading middle cache from Oniooo success, saving cache.\n");
				// Prepend the time to object (the first byte is the "{" initialization)
				string addTimestamp = "\"cachecreatedon\":" + std::to_string(BriandUtils::GetUnixTime()) + ",";
				json->insert(json->begin()+1, addTimestamp.begin(), addTimestamp.end());
				ESP_LOGD(LOGTAG, "[DEBUG] Middle cache from Oniooo will have a size of %u bytes.\n", json->size());

				ofstream f(NODES_FILE_MIDDLE, ios::out | ios::trunc);

				// Buffer has important size, so is better write with buffers of 1K bytes
				while(json->length() > 0) {
					if (json->length() < 1000) {
						f << json->c_str();
						json->clear();
					}
					else {
						f.write(json->c_str(), 1000);
						json->erase(json->begin(), json->begin()+1000);
					}
				}

				f.flush();
				f.close();

				json.reset(); // save ram
				ESP_LOGD(LOGTAG, "[DEBUG] Middle cache from Oniooo saved to %s\n", this->NODES_FILE_MIDDLE);
			}

			tentative++;
		}

		if (tentative == maxTentatives) {
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshOnionooCache permanent failure. exiting.\n");
			return;
		}

		// Finish with exits
		success = false;
		tentative = 0;
		while (!success && tentative < maxTentatives) {
			ESP_LOGD(LOGTAG, "[DEBUG] Downloading exit cache from Oniooo, tentative %d of %d.\n", tentative+1, maxTentatives);
			// Exit nodes => require exit_summary!
			// effective_family and exit_policy_summary removed due to too much bytes...
			auto json = this->GetOnionooJson("relay", "nickname,or_addresses,fingerprint", TOR_FLAGS_EXIT_MUST_HAVE, success, TOR_NODES_CACHE_SIZE);
			if (success) {
				ESP_LOGD(LOGTAG, "[DEBUG] Downloading exit cache from Oniooo success, saving cache.\n");
				// Prepend the time to object (the first byte is the "{" initialization)
				string addTimestamp = "\"cachecreatedon\":" + std::to_string(BriandUtils::GetUnixTime()) + ",";
				json->insert(json->begin()+1, addTimestamp.begin(), addTimestamp.end());
				ESP_LOGD(LOGTAG, "[DEBUG] Middle exit from Oniooo will have a size of %u bytes.\n", json->size());
				
				ofstream f(NODES_FILE_EXIT, ios::out | ios::trunc);

				// Buffer has important size, so is better write with buffers of 1K bytes
				while(json->length() > 0) {
					if (json->length() < 1000) {
						f << json->c_str();
						json->clear();
					}
					else {
						f.write(json->c_str(), 1000);
						json->erase(json->begin(), json->begin()+1000);
					}
				}

				f.flush();
				f.close();
				json.reset(); // save ram
				ESP_LOGD(LOGTAG, "[DEBUG] Exit cache from Oniooo saved to %s\n", this->NODES_FILE_EXIT);
			}

			tentative++;
		}

		if (tentative == maxTentatives) {
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshOnionooCache permanent failure. exiting.\n");
			return;
		}

		// of course....
		this->cacheValid = true;
	}

	bool BriandTorRelaySearcher::CheckCacheFile(const char* filename) {
		bool valid = false;

		ifstream file(filename, ios::in);

		if (file.good()) {
			auto json = make_unique<string>("");
			string line;

			while (file.good()) {
				getline(file, line);
				json->append(line);
			}
			
			file.close();

			cJSON* root = cJSON_Parse(json->c_str());

			if (root == NULL) {
				// Get last error
				const char *error_ptr = cJSON_GetErrorPtr();
				ESP_LOGD(LOGTAG, "[DEBUG] %s cache deserialization error: %s\n", filename, error_ptr);
				// Free resources
				cJSON_Delete(root);
				return false;
			}

			unsigned long int cacheAge = 0;
			auto cacheField = cJSON_GetObjectItemCaseSensitive(root, "cachecreatedon");
			if (cacheField != NULL && cJSON_IsNumber(cacheField)) {
				cacheAge = static_cast<unsigned long int>(cacheField->valueint);
			}

			ESP_LOGD(LOGTAG, "[DEBUG] %s cache created on %lu.\n", filename, cacheAge);

			if ( (cacheAge + (TOR_NODES_CACHE_VAL_H*3600)) >= BriandUtils::GetUnixTime() ) {
				valid = true;
			}

			cJSON_Delete(root);
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] %s cache file does not exist.\n", filename);
		}

		return valid;
	}

	bool BriandTorRelaySearcher::IPsInSameFamily(const string& first, const string& second) {
		struct in_addr ip1, ip2;

		// Convert to in_addr (uint32)
		inet_aton(first.c_str(), &ip1);
		inet_aton(second.c_str(), &ip2);

		// Compare (WARNING: LITTLE ENDIAN!!!! so... take the LAST bytes)
		ip1.s_addr = ip1.s_addr & 0x0000FFFF;
		ip2.s_addr = ip2.s_addr & 0x0000FFFF;

		// Elegant :)
		return ip1.s_addr == ip2.s_addr;
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
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache invalid, download and rebuilding.\n");
			RefreshOnionooCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			ifstream file(this->NODES_FILE_GUARD, ios::in);
			auto json = make_unique<string>("");
			string line;
			while (file.good()) {
				getline(file, line);
				json->append(line);
			}
			file.close();
			cJSON* root = cJSON_Parse(json->c_str());

			if (root == NULL || cJSON_GetObjectItemCaseSensitive(root, "relays") == NULL) {
				// Get last error
				const char *error_ptr = cJSON_GetErrorPtr();
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache deserialization error: %s\n", error_ptr);
				// Free resources
				cJSON_Delete(root);
				return relay;
			}

			auto relays = cJSON_GetObjectItemCaseSensitive(root, "relays");
			if (!cJSON_IsArray(relays)) {
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache deserialization error (no relays array)\n");
				// Free resources
				cJSON_Delete(root);
				return relay;
			}

			relay = make_unique<Briand::BriandTorRelay>();
			int relaysNo = cJSON_GetArraySize(relays);
			while (this->randomPick >= relaysNo)
				this->randomize();
			
			auto randomRelay = cJSON_GetArrayItem(relays, this->randomPick);
			relay->nickname->assign( cJSON_GetObjectItemCaseSensitive(randomRelay, "nickname")->valuestring );
			relay->fingerprint->assign( cJSON_GetObjectItemCaseSensitive(randomRelay, "fingerprint")->valuestring );
			
			// Take first address, separate host and port
			auto addresses = cJSON_GetObjectItemCaseSensitive(randomRelay, "or_addresses");
			string firstAddress = cJSON_GetArrayItem(addresses, 0)->valuestring;
			size_t pos = firstAddress.find(':');
			relay->address->assign(firstAddress.substr(0, pos));
			relay->port = std::stoi(firstAddress.substr(pos+1, 5));

			// Could not be here
			auto effective_family = cJSON_GetObjectItemCaseSensitive(randomRelay, "effective_family");
			if (effective_family != NULL && cJSON_IsString(effective_family))
				relay->effective_family->assign(effective_family->valuestring);
			
			cJSON_Delete(root);
		}
		else {
			ESP_LOGW(LOGTAG, "[DEBUG] Invalid cache at second tentative. Skipping with failure.\n");
		}

		return relay;
	}

	unique_ptr<BriandTorRelay> BriandTorRelaySearcher::GetMiddleRelay(const string& avoidGuardIp) {
		unique_ptr<BriandTorRelay> relay = nullptr;

		if (!this->cacheValid) {
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache invalid, download and rebuilding.\n");
			RefreshOnionooCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			ifstream file(this->NODES_FILE_MIDDLE, ios::in);
			auto json = make_unique<string>("");
			string line;
			while (file.good()) {
				getline(file, line);
				json->append(line);
			}
			file.close();
			cJSON* root = cJSON_Parse(json->c_str());

			if (root == NULL || cJSON_GetObjectItemCaseSensitive(root, "relays") == NULL) {
				// Get last error
				const char *error_ptr = cJSON_GetErrorPtr();
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache deserialization error: %s\n", error_ptr);
				// Free resources
				cJSON_Delete(root);
				return relay;
			}

			auto relays = cJSON_GetObjectItemCaseSensitive(root, "relays");
			if (!cJSON_IsArray(relays)) {
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache deserialization error (no relays array)\n");
				// Free resources
				cJSON_Delete(root);
				return relay;
			}

			relay = make_unique<Briand::BriandTorRelay>();
			int relaysNo = cJSON_GetArraySize(relays);
			
			// Must be avoided the guard IP!
			bool sameFamily = false;

			do {
				do {
					this->randomize();
				} while (this->randomPick >= relaysNo);
				
				auto randomRelay = cJSON_GetArrayItem(relays, this->randomPick);
				relay->nickname->assign( cJSON_GetObjectItemCaseSensitive(randomRelay, "nickname")->valuestring );
				relay->fingerprint->assign( cJSON_GetObjectItemCaseSensitive(randomRelay, "fingerprint")->valuestring );
				
				// Take first address, separate host and port
				auto addresses = cJSON_GetObjectItemCaseSensitive(randomRelay, "or_addresses");
				string firstAddress = cJSON_GetArrayItem(addresses, 0)->valuestring;
				size_t pos = firstAddress.find(':');
				relay->address->assign(firstAddress.substr(0, pos));
				relay->port = std::stoi(firstAddress.substr(pos+1, 5));

				// Check if in the same family
				if (avoidGuardIp.length() > 0) {
					sameFamily = this->IPsInSameFamily(avoidGuardIp, *relay->address.get());
				}
				
				// Could not be here
				auto effective_family = cJSON_GetObjectItemCaseSensitive(randomRelay, "effective_family");
				if (effective_family != NULL && cJSON_IsString(effective_family))
					relay->effective_family->assign(effective_family->valuestring);

			} while (sameFamily);
			
			
			cJSON_Delete(root);
		}
		else {
			ESP_LOGW(LOGTAG, "[DEBUG] Invalid cache at second tentative. Skipping with failure.\n");
		}

		return relay;
	}

	unique_ptr<BriandTorRelay> BriandTorRelaySearcher::GetExitRelay(const string& avoidGuardIp, const string& avoidMiddleIp) {
		unique_ptr<BriandTorRelay> relay = nullptr;

		if (!this->cacheValid) {
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache invalid, download and rebuilding.\n");
			RefreshOnionooCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			ifstream file(this->NODES_FILE_EXIT, ios::in);
			auto json = make_unique<string>("");
			string line;
			while (file.good()) {
				getline(file, line);
				json->append(line);
			}
			file.close();
			cJSON* root = cJSON_Parse(json->c_str());

			if (root == NULL || cJSON_GetObjectItemCaseSensitive(root, "relays") == NULL) {
				// Get last error
				const char *error_ptr = cJSON_GetErrorPtr();
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache deserialization error: %s\n", error_ptr);
				// Free resources
				cJSON_Delete(root);
				return relay;
			}

			auto relays = cJSON_GetObjectItemCaseSensitive(root, "relays");
			if (!cJSON_IsArray(relays)) {
				ESP_LOGD(LOGTAG, "[DEBUG] Guard cache deserialization error (no relays array)\n");
				// Free resources
				cJSON_Delete(root);
				return relay;
			}

			relay = make_unique<Briand::BriandTorRelay>();
			int relaysNo = cJSON_GetArraySize(relays);
			
			// Must be avoided the guard IP and also the middle IP!
			bool sameFamily = false;

			do {
				do {
					this->randomize();
				} while (this->randomPick >= relaysNo);
				
				auto randomRelay = cJSON_GetArrayItem(relays, this->randomPick);
				relay->nickname->assign( cJSON_GetObjectItemCaseSensitive(randomRelay, "nickname")->valuestring );
				relay->fingerprint->assign( cJSON_GetObjectItemCaseSensitive(randomRelay, "fingerprint")->valuestring );
				
				// Take first address, separate host and port
				auto addresses = cJSON_GetObjectItemCaseSensitive(randomRelay, "or_addresses");
				string firstAddress = cJSON_GetArrayItem(addresses, 0)->valuestring;
				size_t pos = firstAddress.find(':');
				relay->address->assign(firstAddress.substr(0, pos));
				relay->port = std::stoi(firstAddress.substr(pos+1, 5));

				// Check if in the same family with guard
				if (avoidGuardIp.length() > 0) {
					sameFamily = this->IPsInSameFamily(avoidGuardIp, *relay->address.get());
				}
				// Check if in the same family with middle
				if (avoidMiddleIp.length() > 0) {
					sameFamily = this->IPsInSameFamily(avoidMiddleIp, *relay->address.get());
				}
				
				// Could not be here
				auto effective_family = cJSON_GetObjectItemCaseSensitive(randomRelay, "effective_family");
				if (effective_family != NULL && cJSON_IsString(effective_family))
					relay->effective_family->assign(effective_family->valuestring);

			} while (sameFamily);
			
			cJSON_Delete(root);
		}
		else {
			ESP_LOGW(LOGTAG, "[DEBUG] Invalid cache at second tentative. Skipping with failure.\n");
		}

		return relay;
	}

	void BriandTorRelaySearcher::InvalidateCache(bool forceRefresh) {
		std::remove(this->NODES_FILE_GUARD);
		std::remove(this->NODES_FILE_MIDDLE);
		std::remove(this->NODES_FILE_EXIT);
		if (forceRefresh) this->RefreshOnionooCache();
	}

	void BriandTorRelaySearcher::PrintCacheContents() {
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] GUARDS CACHE:\n");
			BriandUtils::PrintFileContent(this->NODES_FILE_GUARD);
			printf("\n");
			printf("[DEBUG] MIDDLE CACHE:\n");
			BriandUtils::PrintFileContent(this->NODES_FILE_MIDDLE);
			printf("\n");
			printf("[DEBUG] EXIT CACHE:\n");
			BriandUtils::PrintFileContent(this->NODES_FILE_EXIT);
			printf("\n");
			printf("[DEBUG] Cache status is: %s\n", (this->cacheValid ? "Valid" : "Invalid"));
		}
	}

}