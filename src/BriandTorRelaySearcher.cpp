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
#include "BriandTorDirAuthority.hxx"
#include "BriandTorCryptoUtils.hxx"

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

		// Auth dir enquiry : choose a random one then enquiry another if one fails
		if (TOR_DIR_LAST_USED == 0x0000) {
			TOR_DIR_LAST_USED = BriandUtils::GetRandomByte() % TOR_DIR_AUTHORITIES_NUMBER;
		}

		/* DELTED old implementation
		this->limitRandom = 0;

		// Limit to max 5 result to save RAM!! Never ask for just 1!
		while (this->limitRandom <= 1)
			this->limitRandom = ( Briand::BriandUtils::GetRandomByte() % 5 ) + 1;
		
		// Random pick one from the list
		//this->randomPick = ( Briand::BriandUtils::GetRandomByte() % this->limitRandom );
		
		*/
	}

	/*DELETED unique_ptr<string> BriandTorRelaySearcher::GetOnionooJson(const string& type, const string& fields, const unsigned short& flagsMask, bool& success, const unsigned short overrideLimit) {
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
	*/

	/*DELETED  void BriandTorRelaySearcher::RefreshOnionooCache(const short maxTentatives) {
		
		// CACHE FILE FORMAT:
		// Json file contaning downloaded Onionoo informations PLUS a header field called
		// "cachecreatedon":00000000
		// it contains the timestamp of the last download. If this timestamp is older
		// than TOR_NODES_CACHE_VAL_H than cache must be considered invalid.
		

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
	*/

	void BriandTorRelaySearcher::RefreshNodesCache() {
		/*
			NEW CACHE FILES FORMAT (ascii formats!):
			[TIMESTAMP]\n
			[NICKNAME]\t[FINGERPRINT]\t[IPV4ADDRESS]\t[OR PORT]\t[FLAGS MASK]\n

			each row (except first) is a router. All ASCII format, including integers (port, mask etc.)

		*/

		ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache invoked.\n");
		

		// Start with the first authority, check not to start an infinite loop 
		unsigned short loopStartsWith = 0;
		TOR_DIR_LAST_USED = 1 % TOR_DIR_AUTHORITIES_NUMBER;

		bool cacheCreated = false;
		auto client = make_unique<BriandIDFSocketClient>();
		client->SetVerbose(false);
		client->SetID(100);
		client->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		do {
			auto curDir = TOR_DIR_AUTHORITIES[TOR_DIR_LAST_USED];
			
			// If a previous call did not create good files, restart!

			ofstream fExit(NODES_FILE_EXIT, ios::out | ios::trunc);
			if (!fExit.good()) {
				ESP_LOGE(LOGTAG, "[ERR] RefreshNodesCache FATAL ERROR: Cannot write guard cache file.\n");
				return;
			}
			fExit << std::to_string(BriandUtils::GetUnixTime()) << "\n";
			unsigned char fExitNodes = 0;
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache recreated exit cache.\n");
			
			ofstream fMiddle(NODES_FILE_MIDDLE, ios::out | ios::trunc);
			if (!fMiddle.good()) {
				ESP_LOGE(LOGTAG, "[ERR] RefreshNodesCache FATAL ERROR: Cannot write guard cache file.\n");
				return;
			}
			fMiddle << std::to_string(BriandUtils::GetUnixTime()) << "\n";
			unsigned char fMiddleNodes = 0;
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache recreated middle cache.\n");
			
			ofstream fGuard(NODES_FILE_GUARD, ios::out | ios::trunc);
			if (!fGuard.good()) {
				ESP_LOGE(LOGTAG, "[ERR] RefreshNodesCache FATAL ERROR: Cannot write guard cache file.\n");
				return;
			}
			fGuard << std::to_string(BriandUtils::GetUnixTime()) << "\n";
			unsigned char fGuardNodes = 0;
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache recreated guard cache.\n");

			// Connect
			ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache Connecting to dir #%hu (%s) %s:%hu\n", TOR_DIR_LAST_USED, curDir.nickname, curDir.host, curDir.port);
			if (!client->Connect(string(curDir.host), curDir.port)) {
				ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache Failed to connect to dir #%hu (%s)\n", TOR_DIR_LAST_USED, curDir.nickname);
				TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED+1) % TOR_DIR_AUTHORITIES_NUMBER;
				client->Disconnect();
				continue;
			}

			string path = "/tor/status-vote/current/consensus-microdesc";
			string agent = string(BriandUtils::GetRandomHostName().get());

			auto request = make_unique<string>();
			request->append("GET " + path + " HTTP/1.1\r\n");
			request->append("Host: " + string(curDir.host) + "\r\n");
			request->append("User-Agent: " + agent);
			request->append("\r\n");
			request->append("Connection: close\r\n");
			request->append("\r\n");

			auto requestV = BriandNet::StringToUnsignedCharVector(request, true);

			if (!client->WriteData(requestV)) {
				ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache Failed to write request to dir #%hu (%s)\n", TOR_DIR_LAST_USED, curDir.nickname);
				TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED+1) % TOR_DIR_AUTHORITIES_NUMBER;
				client->Disconnect();
				continue;
			}

			// free ram
			requestV.reset();

			ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache request sent.\n");

			// Now read results (example: http://128.31.0.34:9131/tor/status-vote/current/consensus-microdesc)
			// Searching for "r " string (a row for a starting node)
			bool newLine = false;
			unique_ptr<vector<unsigned char>> rawData = nullptr;

			// This variable is useful: if after a "r " read, while extracting the other lines
			// another unexpected "r " is found, then this variable will be populated and
			// will not read another time.
			unique_ptr<vector<unsigned char>> lostR = nullptr;

			do {
				if (lostR == nullptr) {
					rawData = client->ReadDataUntil('\n', 512, newLine);
				}
				else {
					rawData = std::move(lostR);
					lostR.reset();
				}
					
				if (!newLine || rawData->size() < 2) {
					// something is wrong!
					ESP_LOGD(LOGTAG, "[DEBUG] Wrong read from directory response, newline %s, line is: ", (newLine ? "found" : "not found"));
					if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) BriandUtils::PrintByteBuffer(*rawData.get());
					break;
				}

				// Get a string and free memory
				unique_ptr<string> sData = make_unique<string>();
				for (auto&& c : *rawData.get()) { sData->push_back(static_cast<char>(c)); }

				// If line is a "r " then read informations
				if (sData->substr(0, 2).compare("r ") == 0) {

					sData->erase(0, 2);
					// [NAME] [FINGERPRINT_BASE64] [DATE] [TIME] [IPv4] [ORPORT] 0
					auto pos = sData->find(' ');
					
					if (pos == string::npos) continue;
					
					string rName = sData->substr(0, pos);
					sData->erase(0, pos+1);
					
					pos = sData->find(' ');
					if (pos == string::npos) continue;

					string fingerprintBase64 = sData->substr(0, pos);
					sData->erase(0, pos+1);

					// WARNING: base64 fields could be without the ending '=' but this could be not
					// recognized by a decoding library. So, add the ending '='/'==' to fit
					// the base64 multiples of 4 as required.

					while (fingerprintBase64.length() % 4 != 0)
						fingerprintBase64.push_back('=');

					auto rFingerprintV = BriandTorCryptoUtils::Base64Decode(fingerprintBase64);
					string rFingerprint("");
					for (auto&& c : *rFingerprintV.get()) {
						char buf[3] = {0x00};
						snprintf(buf, 3, "%02X", c);
						rFingerprint.append(buf);
					}
					rFingerprintV.reset();
					
					pos = sData->find(' ');
					if (pos == string::npos) continue;
					// Date: ignore
					sData->erase(0, pos+1);

					pos = sData->find(' ');
					if (pos == string::npos) continue;
					// Time: ignore
					sData->erase(0, pos+1);

					pos = sData->find(' ');
					if (pos == string::npos) continue;
					string rIP = sData->substr(0, pos);
					sData->erase(0, pos+1);

					pos = sData->find(' ');
					if (pos == string::npos) continue;
					string rPort = sData->substr(0, pos);
					sData->erase(0, pos+1);

					// OK! Now there shuld be an "m " line (ignorable)
					rawData = client->ReadDataUntil('\n', 512, newLine);
					if (!newLine || rawData->size() < 2) {
						// error occoured!
						continue;
					}
					if (static_cast<char>(rawData->at(0)) == 'r' && static_cast<char>(rawData->at(1) == ' ')) {
						// a new router line !?!?
						lostR = std::move(rawData);
						continue;
					} 

					// OK! Now there shuld be an "s " line (contains flags!!)
					rawData = client->ReadDataUntil('\n', 512, newLine);
					if (!newLine || rawData->size() < 2) {
						// error occoured!
						continue;
					}
					if (static_cast<char>(rawData->at(0)) == 'r' && static_cast<char>(rawData->at(1) == ' ')) {
						// a new router line !?!?
						lostR = std::move(rawData);
						continue;
					}
					
					// Get a string
					sData = make_unique<string>();
					for (auto&& c : *rawData.get()) { sData->push_back(static_cast<char>(c)); }

					// This line should begin with "s "
					if (sData->substr(0, 2).compare("s ") == 0) {
						unsigned short rFlags = 0x00;

						// rewrite string to uppercase
						for (char& c: *sData.get()) c = std::toupper(c);

						// Check flags
						if (sData->find("AUTHORITY") != string::npos) rFlags = rFlags | BriandTorRelayFlag::AUTHORITY;
						if (sData->find("BADEXIT") != string::npos) rFlags = rFlags | BriandTorRelayFlag::BADEXIT;
						if (sData->find("EXIT") != string::npos) rFlags = rFlags | BriandTorRelayFlag::EXIT;
						if (sData->find("FAST") != string::npos) rFlags = rFlags | BriandTorRelayFlag::FAST;
						if (sData->find("GUARD") != string::npos) rFlags = rFlags | BriandTorRelayFlag::GUARD;
						if (sData->find("HSDIR") != string::npos) rFlags = rFlags | BriandTorRelayFlag::HSDIR;
						if (sData->find("NOEDCONSENSUS") != string::npos) rFlags = rFlags | BriandTorRelayFlag::NOEDCONSENSUS;
						if (sData->find("RUNNING") != string::npos) rFlags = rFlags | BriandTorRelayFlag::RUNNING;
						if (sData->find("STABLE") != string::npos) rFlags = rFlags | BriandTorRelayFlag::STABLE;
						if (sData->find("STABLEDESC") != string::npos) rFlags = rFlags | BriandTorRelayFlag::STABLEDESC;
						if (sData->find("V2DIR") != string::npos) rFlags = rFlags | BriandTorRelayFlag::V2DIR;
						if (sData->find("VALID") != string::npos) rFlags = rFlags | BriandTorRelayFlag::VALID;

						// Check if this node is suitable as EXIT, GUARD or MIDDLE
						if (fExitNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_EXIT_MUST_HAVE) == TOR_FLAGS_EXIT_MUST_HAVE ) {
							fExit << rName << "\t";
							fExit << rFingerprint << "\t";
							fExit << rIP << "\t";
							fExit << rPort << "\t";
							fExit << std::to_string(rFlags) << "\t";
							if (fExitNodes+1 < TOR_NODES_CACHE_SIZE) fExit << "\n"; // skip last \n
							fExitNodes++;
						}
						else if (fGuardNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_GUARD_MUST_HAVE) == TOR_FLAGS_GUARD_MUST_HAVE ) {
							fGuard << rName << "\t";
							fGuard << rFingerprint << "\t";
							fGuard << rIP << "\t";
							fGuard << rPort << "\t";
							fGuard << std::to_string(rFlags) << "\t";
							if (fGuardNodes+1 < TOR_NODES_CACHE_SIZE) fGuard << "\n"; // skip last \n
							fGuardNodes++;
						}
						else if (fMiddleNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_MIDDLE_MUST_HAVE) == TOR_FLAGS_MIDDLE_MUST_HAVE ) {
							fMiddle << rName << "\t";
							fMiddle << rFingerprint << "\t";
							fMiddle << rIP << "\t";
							fMiddle << rPort << "\t";
							fMiddle << std::to_string(rFlags) << "\t";
							if (fMiddleNodes+1 < TOR_NODES_CACHE_SIZE) fMiddle << "\n"; // skip last \n
							fMiddleNodes++;
						}
					}
				}

				// Cache ready?
				cacheCreated = (fExitNodes >= TOR_NODES_CACHE_SIZE && fMiddleNodes >= TOR_NODES_CACHE_SIZE && fGuardNodes >= TOR_NODES_CACHE_SIZE);

			} while (rawData->size() > 0 && !cacheCreated);

			// If cache not ready, go to next dir
			if (!cacheCreated) {
				TOR_DIR_LAST_USED = (TOR_DIR_LAST_USED+1) % TOR_DIR_AUTHORITIES_NUMBER;
			}

			// Disconnect the client
			client->Disconnect();

			// Close files
			fExit.flush();
			fExit.close();
			fMiddle.flush();
			fMiddle.close();
			fGuard.flush();
			fGuard.close();

		} while (!cacheCreated && loopStartsWith != TOR_DIR_LAST_USED);

		// If all dirs fault
		if (loopStartsWith == TOR_DIR_LAST_USED && !cacheCreated) {
			ESP_LOGE(LOGTAG, "[ERR] RefreshNodesCache FATAL ERROR: all directories failed to build a cache. Too many TOR Nodes required in cache? Network down? TOR dirs all down?\n");
		}
	}

	bool BriandTorRelaySearcher::CheckCacheFile(const char* filename) {
		bool valid = false;

		ifstream file(filename, ios::in);

		if (file.good()) {
			/* OLD Onionoo implementation
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
			*/

			// Check just the first line timestamp and how many lines are in the file
			string firstLine("");
			std::getline(file, firstLine, '\n');
			unsigned int lines = 0;
			string temp;
			while (!file.eof()) { 
				std::getline(file, temp, '\n');
				lines++;
			}
			file.close(); 

			ESP_LOGD(LOGTAG, "[DEBUG] %s cache file has %u rows.\n", filename, lines);

			if (firstLine.size() > 3) {
				unsigned long int cacheAge = stoul(firstLine);
				if ( (cacheAge + (TOR_NODES_CACHE_VAL_H*3600)) >= BriandUtils::GetUnixTime() ) {
					valid = true;
				}
				if (lines < TOR_NODES_CACHE_SIZE) {
					valid = false;
				}
			}	
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
			/* OLD Onionoo implementation
			RefreshOnionooCache();
			*/
			RefreshNodesCache();
		}
		if (this->cacheValid) {
			// randomize for random picking
			this->randomize();
			
			ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

			ifstream file(this->NODES_FILE_GUARD, ios::in);

			// Skip the first line
			string line; 
			std::getline(file, line, '\n');

			// Try to reach line number, if fails randomize again
			bool validLine = false;
			unsigned char fileLines = 0;
			while (!validLine) {
				if (file.eof()) {
					// Here file is EOF but line was not reached, so check.
					while (this->randomPick >= fileLines) 
						this->randomize();

					// restart
					fileLines = 0;
					file.seekg(0);
					std::getline(file, line, '\n');
				}

				if (fileLines != this->randomPick) {
					std::getline(file, line, '\n');
					fileLines++;
				}
				else {
					// We're in the right line
					validLine = true;
				}
			}

			file.close();

			// If line is empty or not valid, error
			if (line.size() < 32) {
				ESP_LOGW(LOGTAG, "[WARN] Cache file is not valid.\n");
				std::remove(NODES_FILE_MIDDLE);
				return relay;
			}

			// At this point (should always arrive there!) create the relay object
			relay = make_unique<Briand::BriandTorRelay>();
			
			relay->nickname->assign( line.substr(0, line.find('\t')) );
			line.erase(0, line.find('\t')+1);
			
			relay->fingerprint->assign( line.substr(0, line.find('\t')) );
			line.erase(0, line.find('\t')+1);
			
			relay->address->assign( line.substr(0, line.find('\t')) );
			line.erase(0, line.find('\t')+1);

			relay->port = std::stoi( line.substr(0, line.find('\t')) );
			// unecessary till new fields to manage
			// line.erase(0, line.find('\t')+1);
			

			/* OLD Onionoo implementation
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
			*/
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
			/* OLD Onionoo implementation
			RefreshOnionooCache();
			*/
		}
		if (this->cacheValid) {
			bool sameFamily = true;

			do {
				// randomize for random picking
				this->randomize();
				
				ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

				ifstream file(this->NODES_FILE_MIDDLE, ios::in);

				// Skip the first line
				string line; 
				std::getline(file, line, '\n');

				// Try to reach line number, if fails randomize again
				bool validLine = false;
				unsigned char fileLines = 0;
				while (!validLine) {
					if (file.eof()) {
						// Here file is EOF but line was not reached, so check.
						while (this->randomPick >= fileLines) 
							this->randomize();

						// restart
						fileLines = 0;
						file.seekg(0);
						std::getline(file, line, '\n');
					}

					if (fileLines != this->randomPick) {
						std::getline(file, line, '\n');
						fileLines++;
					}
					else {
						// We're in the right line
						validLine = true;
					}
				}

				file.close();

				// If line is empty or not valid, error
				if (line.size() < 32) {
					ESP_LOGW(LOGTAG, "[WARN] Cache file is not valid.\n");
					std::remove(NODES_FILE_MIDDLE);
					return relay;
				}

				// At this point (should always arrive there!) create the relay object
				relay = make_unique<Briand::BriandTorRelay>();
				
				relay->nickname->assign( line.substr(0, line.find('\t')) );
				line.erase(0, line.find('\t')+1);
				
				relay->fingerprint->assign( line.substr(0, line.find('\t')) );
				line.erase(0, line.find('\t')+1);
				
				relay->address->assign( line.substr(0, line.find('\t')) );
				line.erase(0, line.find('\t')+1);

				relay->port = std::stoi( line.substr(0, line.find('\t')) );
				// unecessary till new fields to manage
				// line.erase(0, line.find('\t')+1);

				// Check if in the same family
				if (avoidGuardIp.length() > 0) {
					sameFamily = this->IPsInSameFamily(avoidGuardIp, *relay->address.get());
				}

			} while (sameFamily);

			/* OLD Onionoo implementation
			
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
			*/
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
			/* OLD Onionoo implementation
			RefreshOnionooCache();
			*/
		}
		if (this->cacheValid) {
			bool sameFamily = false;

			do {
				// randomize for random picking
				this->randomize();
				
				ESP_LOGD(LOGTAG, "[DEBUG] Nodes cache is valid. Picking random node #%d.\n", this->randomPick);

				ifstream file(this->NODES_FILE_EXIT, ios::in);

				// Skip the first line
				string line; 
				std::getline(file, line, '\n');

				// Try to reach line number, if fails randomize again
				bool validLine = false;
				unsigned char fileLines = 0;
				while (!validLine) {
					if (file.eof()) {
						// Here file is EOF but line was not reached, so check.
						while (this->randomPick >= fileLines) 
							this->randomize();

						// restart
						fileLines = 0;
						file.seekg(0);
						std::getline(file, line, '\n');
					}

					if (fileLines != this->randomPick) {
						std::getline(file, line, '\n');
						fileLines++;
					}
					else {
						// We're in the right line
						validLine = true;
					}
				}

				file.close();

				// If line is empty or not valid, error
				if (line.size() < 32) {
					ESP_LOGW(LOGTAG, "[WARN] Cache file is not valid.\n");
					std::remove(NODES_FILE_EXIT);
					return relay;
				}

				// At this point (should always arrive there!) create the relay object
				relay = make_unique<Briand::BriandTorRelay>();
				
				relay->nickname->assign( line.substr(0, line.find('\t')) );
				line.erase(0, line.find('\t')+1);
				
				relay->fingerprint->assign( line.substr(0, line.find('\t')) );
				line.erase(0, line.find('\t')+1);
				
				relay->address->assign( line.substr(0, line.find('\t')) );
				line.erase(0, line.find('\t')+1);

				relay->port = std::stoi( line.substr(0, line.find('\t')) );
				// unecessary till new fields to manage
				// line.erase(0, line.find('\t')+1);

				// Check if in the same family with guard
				if (avoidGuardIp.length() > 0) {
					sameFamily = this->IPsInSameFamily(avoidGuardIp, *relay->address.get());
				}
				// Check if in the same family with middle
				if (avoidMiddleIp.length() > 0) {
					sameFamily = sameFamily || this->IPsInSameFamily(avoidMiddleIp, *relay->address.get());
				}

			} while (sameFamily);

			/* OLD Onionoo implementation



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
					sameFamily = sameFamily || this->IPsInSameFamily(avoidMiddleIp, *relay->address.get());
				}
				
				// Could not be here
				auto effective_family = cJSON_GetObjectItemCaseSensitive(randomRelay, "effective_family");
				if (effective_family != NULL && cJSON_IsString(effective_family))
					relay->effective_family->assign(effective_family->valuestring);

			} while (sameFamily);
			
			cJSON_Delete(root);
			
			*/
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
		if (forceRefresh) {
			/* OLD Onionoo implementation
			RefreshOnionooCache();
			*/
			this->RefreshNodesCache();
		}
	}

	void BriandTorRelaySearcher::PrintCacheContents() {
		if (true || esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
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

	size_t BriandTorRelaySearcher::GetObjectSize() {
		size_t oSize = 0;

		oSize += sizeof(*this);
		oSize += sizeof(this->NODES_FILE_EXIT) + sizeof(char)*strlen(this->NODES_FILE_EXIT);
		oSize += sizeof(this->NODES_FILE_GUARD) + sizeof(char)*strlen(this->NODES_FILE_GUARD);
		oSize += sizeof(this->NODES_FILE_MIDDLE) + sizeof(char)*strlen(this->NODES_FILE_MIDDLE);

		return oSize;
	}

	void BriandTorRelaySearcher::PrintObjectSizeInfo() {
		printf("sizeof(*this) = %zu\n", sizeof(*this));
		printf("sizeof(this->NODES_FILE_EXIT) + sizeof(char)*strlen(this->NODES_FILE_EXIT) = %zu\n", sizeof(this->NODES_FILE_EXIT) + sizeof(char)*strlen(this->NODES_FILE_EXIT));
		printf("sizeof(this->NODES_FILE_GUARD) + sizeof(char)*strlen(this->NODES_FILE_GUARD) = %zu\n", sizeof(this->NODES_FILE_GUARD) + sizeof(char)*strlen(this->NODES_FILE_GUARD));
		printf("sizeof(this->NODES_FILE_MIDDLE) + sizeof(char)*strlen(this->NODES_FILE_MIDDLE) = %zu\n", sizeof(this->NODES_FILE_MIDDLE) + sizeof(char)*strlen(this->NODES_FILE_MIDDLE));

		printf("TOTAL = %zu\n", this->GetObjectSize());
	}

}