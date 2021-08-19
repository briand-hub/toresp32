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

	const char* BriandTorRelaySearcher::LOGTAG = "briandsearch";

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
	}

	void BriandTorRelaySearcher::RefreshNodesCache() {
		/*
			NEW CACHE FILES FORMAT (ascii formats!):
			[TIMESTAMP]\n
			[NICKNAME]\t[FINGERPRINT]\t[IPV4ADDRESS]\t[OR PORT]\t[FLAGS MASK]\n

			each row (except first) is a router. All ASCII format, including integers (port, mask etc.)

		*/

		ESP_LOGD(LOGTAG, "[DEBUG] RefreshNodesCache invoked.\n");
		
		// Always show an alert because this is a long operation!
		printf("\n\n*** System warning: Tor node cache is rebuilding, may take time.\n\n");

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

			string path = "/tor/status-vote/current/consensus";
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

			// Now read results (example: http://45.66.33.45/tor/status-vote/current/consensus)
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
					// [NAME] [FINGERPRINT_BASE64] [OTHER_BASE64] [DATE] [TIME] [IPv4] [ORPORT] 0
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
					// Other info base64: ignore
					sData->erase(0, pos+1);
					
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
					// Not listed in full consensus
					// rawData = client->ReadDataUntil('\n', 512, newLine);
					// if (!newLine || rawData->size() < 2) {
					// 	// error occoured!
					// 	continue;
					// }
					// if (static_cast<char>(rawData->at(0)) == 'r' && static_cast<char>(rawData->at(1) == ' ')) {
					// 	// a new router line !?!?
					// 	lostR = std::move(rawData);
					// 	continue;
					// } 

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

						// If Exit node and some ports in the settings TOR_MUST_HAVE_PORTS, check the policy
						bool exitCheck = true;
						if (TOR_MUST_HAVE_PORTS_SIZE > 0 && fExitNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_EXIT_MUST_HAVE) == TOR_FLAGS_EXIT_MUST_HAVE) {
							// Read data until a "p " line is reached
							bool policyFound = false;
							while (!policyFound) {
								rawData = client->ReadDataUntil('\n', 512, newLine);
								if (!newLine || rawData->size() < 2) {
									// error occoured!
									exitCheck = false;
									break;
								}
								if (static_cast<char>(rawData->at(0)) == 'r' && static_cast<char>(rawData->at(1) == ' ')) {
									// a new router line !?!?
									lostR = std::move(rawData);
									exitCheck = false;
									break;
								}
								if (static_cast<char>(rawData->at(0)) == 'p' && static_cast<char>(rawData->at(1) == ' ')) {
									policyFound = true;
									/*
										"p" SP ("accept" / "reject") SP PortList NL

										[At most once.]

										PortList = PortOrRange
										PortList = PortList "," PortOrRange
										PortOrRange = INT "-" INT / INT

										A list of those ports that this router supports (if 'accept') or does not support (if 'reject') for exit to "most addresses".
									*/
									
									// Convert to string, use same buffers
									sData->clear();
									for (auto&& c : *rawData.get()) { sData->push_back(static_cast<char>(c)); }
									sData->erase(0, 2); // erase first chars

									// "accept"/"reject" has same length, so...
									string policyType = sData->substr(0, 7);
									policyType.pop_back(); // remove space
									sData->erase(0, 7); // leave the port list only

									if (policyType.compare("accept") == 0) {
										// Check ports are listed
										for (unsigned char i = 0; i < TOR_MUST_HAVE_PORTS_SIZE; i++) {
											exitCheck = exitCheck && this->IsPortListed(TOR_MUST_HAVE_PORTS[i], *sData.get());
										}
									}
									else if (policyType.compare("reject") == 0) {
										// Check ports are NOT listed
										for (unsigned char i = 0; i < TOR_MUST_HAVE_PORTS_SIZE; i++) {
											exitCheck = exitCheck && !this->IsPortListed(TOR_MUST_HAVE_PORTS[i], *sData.get());
										}
									}
									else {
										// Whooops...
										exitCheck = false;
									}
								}
							}
						}
						else {
							// It is not the case, so true by default
							exitCheck = true;
						}

						// Check if this node is suitable as EXIT, GUARD or MIDDLE
						// If the exitCheck is false then exit node is not suitable or an "r " line has been found, so error, do not insert anything!
						if (exitCheck && fExitNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_EXIT_MUST_HAVE) == TOR_FLAGS_EXIT_MUST_HAVE) {
							fExit << rName << "\t";
							fExit << rFingerprint << "\t";
							fExit << rIP << "\t";
							fExit << rPort << "\t";
							fExit << std::to_string(rFlags) << "\t";
							if (fExitNodes+1 < TOR_NODES_CACHE_SIZE) fExit << "\n"; // skip last \n
							fExitNodes++;
						}
						else if (exitCheck && fGuardNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_GUARD_MUST_HAVE) == TOR_FLAGS_GUARD_MUST_HAVE) {
							fGuard << rName << "\t";
							fGuard << rFingerprint << "\t";
							fGuard << rIP << "\t";
							fGuard << rPort << "\t";
							fGuard << std::to_string(rFlags) << "\t";
							if (fGuardNodes+1 < TOR_NODES_CACHE_SIZE) fGuard << "\n"; // skip last \n
							fGuardNodes++;
						}
						else if (exitCheck && fMiddleNodes < TOR_NODES_CACHE_SIZE && (rFlags & TOR_FLAGS_MIDDLE_MUST_HAVE) == TOR_FLAGS_MIDDLE_MUST_HAVE) {
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

	bool BriandTorRelaySearcher::IsPortListed(const unsigned short& port, const string& portList) {
		size_t posStart = 0;
		size_t posEnd = 0;
		while (posStart < portList.size()) {
			posEnd = portList.find(',', posStart);
			
			if (posEnd == string::npos && posStart < portList.length()) {
				// This is the last entry, take all the remaining.
				posEnd = portList.length();
			}
			
			if (posEnd != string::npos) {
				string temp = portList.substr(posStart, posEnd-posStart);
				
				size_t rangeSepPos = temp.find("-");
				if (rangeSepPos == string::npos) {
					// Single entry
					if (port == atoi(temp.c_str())) {
						return true;
					}
				}
				else {
					// Range entry
					unsigned short min, max, swap;
					min = atoi(temp.substr(0, rangeSepPos).c_str());
					max = atoi(temp.substr(rangeSepPos+1, temp.length()-rangeSepPos).c_str());
					// ensure order
					if (min > max) {
						swap = min;
						min = max;
						max = swap;
					}

					if (port >= min && port <= max) {
						return true;
					}
				}
								
				posStart = posEnd + 1;
			}
		}

		// When arrives here, sure not listed!
		return false;
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