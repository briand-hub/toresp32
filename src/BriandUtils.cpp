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

#include "BriandUtils.hxx"

#include <esp_system.h>

#include <iostream>
#include <memory>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandNet.hxx"

using namespace std;

namespace Briand
{

	unsigned char BriandUtils::GetRandomByte() {
		// default_random_engine generator;	
		// uniform_int_distribution<int> distribution(0x00, 0xFF); 
		// return distribution(generator);

		// return static_cast<unsigned char>( esp_random() );

		// Better implementation, best if wifi is enabled

		return static_cast<unsigned char>( esp_random() % 0x100 );
	}

	unique_ptr<unsigned char[]> BriandUtils::GetRandomMAC() {
		auto mac = make_unique<unsigned char[]>(6);
		
		mac[0] = GetRandomByte();
		mac[1] = GetRandomByte();
		mac[2] = GetRandomByte();
		mac[3] = GetRandomByte();
		mac[4] = GetRandomByte();
		mac[5] = GetRandomByte();

		return mac;
	}

	unique_ptr<char[]> BriandUtils::GetRandomHostName() {
		auto temp = make_unique<char[]>(WIFI_HOSTNAME_LEN + 1);
		unsigned char counter = 0;

		// Use only alphanumeric ascii-chars [a-z][A-Z][0-9]
		while (counter < WIFI_HOSTNAME_LEN) {
			unsigned char randomChar = GetRandomByte();
			if ( 
				(randomChar >= 0x30 && randomChar <= 0x39) || 
				(randomChar >= 0x41 && randomChar <= 0x5A) ||
				(randomChar >= 0x61 && randomChar <= 0x7A)
			) {
				temp[counter] = randomChar;
				counter++;
			}
		}

		temp [WIFI_HOSTNAME_LEN] = '\0'; // null terminate string!

		return move(temp);
	}

	unique_ptr<char[]> BriandUtils::GetRandomSSID() {
		auto temp = make_unique<char[]>(WIFI_AP_SSID_LEN + 1);
		unsigned char counter = 0;

		// Use only alphanumeric ascii-chars [a-z][A-Z][0-9]
		while (counter < WIFI_AP_SSID_LEN) {
			unsigned char randomChar = GetRandomByte();
			if ( 
				(randomChar >= 0x30 && randomChar <= 0x39) || 
				(randomChar >= 0x41 && randomChar <= 0x5A) ||
				(randomChar >= 0x61 && randomChar <= 0x7A)
			) {
				temp[counter] = randomChar;
				counter++;
			}
		}

		temp [WIFI_AP_SSID_LEN] = '\0'; // null terminate string!

		return move(temp);
	}

	unique_ptr<char[]> BriandUtils::GetRandomPassword(int length) {
		auto temp = make_unique<char[]>(length + 1);
		unsigned char counter = 0;

		// Use useful ASCII chars
		while (counter < length) {
			unsigned char randomChar = GetRandomByte();
			if (randomChar != 0x60 && (randomChar >= 0x21 && randomChar <= 0x7E)) {
				temp[counter] = randomChar;
				counter++;
			}
		}

		temp[length] = '\0'; // null terminate string!

		return move(temp);
	}

	string BriandUtils::BriandTorRelayFlagsToString(unsigned short flagMask, const string& prepend /* = ""*/, const string& separator /* = " "*/) {
		string output("");

		if (flagMask & Briand::BriandTorRelayFlag::AUTHORITY) {
			output.append(prepend);
			output.append("Authority");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::BADEXIT) {
			output.append(prepend);
			output.append("BadExit");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::EXIT) {
			output.append(prepend);
			output.append("Exit");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::FAST) {
			output.append(prepend);
			output.append("Fast");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::GUARD) {
			output.append(prepend);
			output.append("Guard");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::HSDIR) {
			output.append(prepend);
			output.append("HSDir");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::NOEDCONSENSUS) {
			output.append(prepend);
			output.append("NoEdConsensus");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::RUNNING) {
			output.append(prepend);
			output.append("Running");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::STABLE) {
			output.append(prepend);
			output.append("Stable");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::STABLEDESC) {
			output.append(prepend);
			output.append("StableDesc");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::V2DIR) {
			output.append(prepend);
			output.append("V2Dir");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::VALID) {
			output.append(prepend);
			output.append("Valid");
			output.append(separator);
		} 
		if (flagMask & Briand::BriandTorRelayFlag::AUTHORITY) {
			output.append(prepend);
			output.append("Authority");
			output.append(separator);
		} 

		if (output.length() > 0)
			output.resize(output.length() - separator.length()); // remove last separator

		return output;
	}

	string BriandUtils::BriandIfConfigMe() {
		bool success = false;
		short httpCode = 0;
		string randomAgent = string( Briand::BriandUtils::GetRandomHostName().get() );

		cJSON* doc = Briand::BriandNet::HttpsGetJson("ifconfig.me", 443, "/all.json", httpCode, success, randomAgent);

		// Prepare output
		string output("");

		if (success) {
			auto ip_addr = cJSON_GetObjectItemCaseSensitive(doc, "ip_addr");
			auto remote_host = cJSON_GetObjectItemCaseSensitive(doc, "remote_host");
			auto user_agent = cJSON_GetObjectItemCaseSensitive(doc, "user_agent");
			auto port = cJSON_GetObjectItemCaseSensitive(doc, "port");
			auto language = cJSON_GetObjectItemCaseSensitive(doc, "language");
			auto encoding = cJSON_GetObjectItemCaseSensitive(doc, "encoding");
			auto mime = cJSON_GetObjectItemCaseSensitive(doc, "mime");
			auto via = cJSON_GetObjectItemCaseSensitive(doc, "via");
			auto forwarded = cJSON_GetObjectItemCaseSensitive(doc, "forwarded");

			if (ip_addr != NULL && ip_addr->valuestring != NULL) {
				output.append("[IFCONFIG.me Public ip]: ");
				output.append( ip_addr->valuestring );
				output.append("\n");
			}
			if (remote_host != NULL && remote_host->valuestring != NULL) {
				output.append("[IFCONFIG.me Remote host]: ");
				output.append( remote_host->valuestring );
				output.append("\n");
			}
			if (user_agent != NULL && user_agent->valuestring != NULL) {
				output.append("[IFCONFIG.me User-Agent]: ");
				output.append( user_agent->valuestring );
				output.append("\n");
			}
			if (port != NULL && cJSON_IsNumber(port)) {
				output.append("[IFCONFIG.me Port]: ");
				output.append( std::to_string( port->valueint ) );
				output.append("\n");
			}
			if (language != NULL && language->valuestring != NULL) {
				output.append("[IFCONFIG.me Language]: ");
				output.append( language->valuestring );
				output.append("\n");
			}
			if (encoding != NULL && encoding->valuestring != NULL) {
				output.append("[IFCONFIG.me Encoding]: ");
				output.append( encoding->valuestring );
				output.append("\n");
			}
			if (mime != NULL && mime->valuestring != NULL) {
				output.append("[IFCONFIG.me Mime]: ");
				output.append( mime->valuestring );
				output.append("\n");
			}
			if (via != NULL && via->valuestring != NULL) {
				output.append("[IFCONFIG.me Via]: ");
				output.append( via->valuestring );
				output.append("\n");
			}
			if (forwarded != NULL && forwarded->valuestring != NULL) {
				output.append("[IFCONFIG.me Forwarded]: ");
				output.append( forwarded->valuestring );
				output.append("\n");
			}
		}
		else {
			ESP_LOGW(LOGTAG, "[ERR] Error on downloading from https://ifconfig.me/all.json Http code: %d Deserialization success: %d\n", httpCode, success);
		}

		cJSON_Delete(doc);

		return output;
	}

	string BriandUtils::BriandGetPublicIPFromIfConfigMe() {
		bool success = false;
		short httpCode = 0;
		string randomAgent = string( Briand::BriandUtils::GetRandomHostName().get() );

		cJSON* doc = Briand::BriandNet::HttpsGetJson("ifconfig.me", 443, "/all.json", httpCode, success, randomAgent);

		// Prepare output
		string output("");

		if (success) {
			auto ip_addr = cJSON_GetObjectItemCaseSensitive(doc, "ip_addr");

			if (ip_addr != NULL && ip_addr->valuestring != NULL) {
				output.assign(ip_addr->valuestring);
			}
		}
		else {
			ESP_LOGW(LOGTAG, "[ERR] Error on downloading IP Informations from https://ifconfig.me/all.json Http code: %d Deserialization success: %d\n", httpCode, success);
		}

		cJSON_Delete(doc);

		return output;
	}

	void BriandUtils::PrintByteBuffer(const vector<unsigned char>& buffer, const short& newLineAfterBytes /* = 0 */, const unsigned int& bytesToPrint /* = 0 */) {
		unsigned int limit;

		if (bytesToPrint > 0 && bytesToPrint < buffer.size()) limit = bytesToPrint;
		else limit = buffer.size();

		for (unsigned int i=0; i < limit; i++) {
			printf("%02X", buffer.at(i));
			if (newLineAfterBytes > 0 && i > 0 && i % newLineAfterBytes == 0) printf("\n");
		}
		printf("\n");
	}

	void BriandUtils::PrintOldStyleByteBuffer(unsigned char buffer[], const unsigned int& size, const short& newLineAfterBytes /* = 0 */, const unsigned int& bytesToPrint /* = 0 */) {
		unsigned int limit;

		if (bytesToPrint > 0 && bytesToPrint < size) limit = bytesToPrint;
		else limit = size;

		for (unsigned int i=0; i < limit; i++) {
			printf("%02X", buffer[i]);
			if (newLineAfterBytes > 0 && i > 0 && i % newLineAfterBytes == 0) printf("\n");
		}
		printf("\n");
	}

	string BriandUtils::BriandTorCellCommandToString(const Briand::BriandTorCellCommand& command) {
		if (command == Briand::BriandTorCellCommand::PADDING) return string("PADDING");
		if (command == Briand::BriandTorCellCommand::CREATE) return string("CREATE");
		if (command == Briand::BriandTorCellCommand::CREATED) return string("CREATED");
		if (command == Briand::BriandTorCellCommand::RELAY) return string("RELAY");
		if (command == Briand::BriandTorCellCommand::DESTROY) return string("DESTROY");
		if (command == Briand::BriandTorCellCommand::CREATE_FAST) return string("CREATE_FAST");
		if (command == Briand::BriandTorCellCommand::CREATED_FAST) return string("CREATED_FAST");
		if (command == Briand::BriandTorCellCommand::NETINFO) return string("NETINFO");
		if (command == Briand::BriandTorCellCommand::RELAY_EARLY) return string("RELAY_EARLY");
		if (command == Briand::BriandTorCellCommand::CREATE2) return string("CREATE2");
		if (command == Briand::BriandTorCellCommand::CREATED2) return string("CREATED2");
		if (command == Briand::BriandTorCellCommand::PADDING_NEGOTIATE) return string("PADDING_NEGOTIATE");
		if (command == Briand::BriandTorCellCommand::VERSIONS) return string("VERSIONS");
		if (command == Briand::BriandTorCellCommand::VPADDING) return string("VPADDING");
		if (command == Briand::BriandTorCellCommand::CERTS) return string("CERTS");
		if (command == Briand::BriandTorCellCommand::AUTH_CHALLENGE) return string("AUTH_CHALLENGE");
		if (command == Briand::BriandTorCellCommand::AUTHENTICATE) return string("AUTHENTICATE");
		if (command == Briand::BriandTorCellCommand::AUTHORIZE) return string("AUTHORIZE");

		return string("UNKNOWN");
	}

	string BriandUtils::BriandTorRelayCellCommandToString(const Briand::BriandTorCellRelayCommand& command) {
		if (command == Briand::BriandTorCellRelayCommand::RELAY_BEGIN) return string("RELAY_BEGIN");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_BEGIN_DIR) return string("RELAY_BEGIN_DIR");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_CONNECTED) return string("RELAY_CONNECTED");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_DATA) return string("RELAY_DATA");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_DROP) return string("RELAY_DROP");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_END) return string("RELAY_END");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_EXTEND2) return string("RELAY_EXTEND2");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_EXTEND) return string("RELAY_EXTEND");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_EXTENDED2) return string("RELAY_EXTENDED2");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_EXTENDED) return string("RELAY_EXTENDED");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_RESOLVE) return string("RELAY_RESOLVE");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_RESOLVED) return string("RELAY_RESOLVED");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_SENDME) return string("RELAY_SENDME");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_TRUNCATE) return string("RELAY_TRUNCATE");
		if (command == Briand::BriandTorCellRelayCommand::RELAY_TRUNCATED) return string("RELAY_TRUNCATED");

		return string("UNKNOWN");
	}

	unique_ptr<unsigned char[]> BriandUtils::GetOneOldBuffer(const unsigned int& size) {
		auto buf = make_unique<unsigned char[]>(size);
		// init to zero
		for (unsigned int i = 0; i<size; i++) {
			buf[i] = 0x00;
		}

		return std::move(buf);
	}

	unsigned long BriandUtils::GetUnixTime() {
		long int now;
		time(&now);
		return now;
	}

	unique_ptr<unsigned char[]> BriandUtils::VectorToArray(const unique_ptr<vector<unsigned char>>& input) {
		auto b = make_unique<unsigned char[]>(input->size());
		for (unsigned long int i = 0; i < input->size(); i++)
			b[i] = input->at(i);
		return std::move(b);
	}

	unique_ptr<vector<unsigned char>> BriandUtils::ArrayToVector(const unique_ptr<unsigned char[]>& input, const unsigned long int& size) {
		auto v = make_unique<vector<unsigned char>>();
		for (int i = 0; i < size; i++)
			v->push_back(input[i]);
		return std::move(v);
	}

	unique_ptr<unsigned char[]> BriandUtils::StringToOldBuffer(const string& input, bool nullterminate /* = false*/) {
		unsigned long int size = input.length();

		if (nullterminate) size++;

		auto b = make_unique<unsigned char[]>(size);
		for (unsigned long int i = 0; i < input.length(); i++)
			b[i] = input.at(i);

		return std::move(b);
	}

	string BriandUtils::OldBufferToString(unique_ptr<unsigned char[]>& input, const unsigned long int& size) {
		string output("");
		unsigned long int limit = size;

		// If null-terminated string, do not include
		if (input[size-1] == 0x00) limit--;

		for (unsigned long int i = 0; i < limit; i++) 
			output.push_back(input[i]);
		
		return output;
	}

	unique_ptr<vector<unsigned char>> BriandUtils::HexStringToVector(const string& hexstring, const string& preNonHex) {
		auto v = make_unique<vector<unsigned char>>();

		if (hexstring.length() % 2 != 0)
			return std::move(v);

		// Copy prepended if any
		for (unsigned long int i = 0; i < preNonHex.length(); i++) {	
			v->push_back( static_cast<unsigned char>( preNonHex.at(i) ) );
		}

		// Copy other bytes, 2 digits per time
		for (unsigned long int i = 0; i < hexstring.length(); i+= 2) {			
			string h("");
			h.push_back(hexstring.at(i));
			h.push_back(hexstring.at(i+1));

			v->push_back( static_cast<unsigned char>( std::stoi(h, 0, 16) ) );
		}

		return std::move(v);
	}

	unique_ptr<unsigned char[]> BriandUtils::HexStringToOldBuffer(const string& hexstring, unsigned int& size, const string& preNonhex, bool nullterm /* = false */) {
		unsigned int i = 0;
		unsigned int j = 0;
		
		size = (hexstring.length()/2) + preNonhex.length(); 
		if( nullterm ) size++;

		auto buffer = make_unique<unsigned char[]>(size);

		if (hexstring.length() % 2 != 0)
			return std::move(buffer);
		
		// init to zero is granted by make_unique
		
		// copy prepended if any
		for (i = 0; i < preNonhex.length(); i++) {
			buffer[j] = preNonhex.at(i);
			j++;
		}

		// Copy 2 digits per time
		for (i = 0; i < hexstring.length(); i += 2) {
			string b = string("");
			b.push_back(hexstring.at(i));
			b.push_back(hexstring.at(i+1));

			buffer[j] = static_cast<unsigned char>( stoi( b, 0, 16 ) );
			j++;
		}

		return std::move(buffer);
	}

	void BriandUtils::PrintFileContent(const string& filename) {
		ifstream f;
		f.open(filename, ios::binary | ios::in);
		unsigned char c = f.get();
		while (f.good()) {
			cout << c;
			c = f.get();
		}
		f.close();
	}

	void BriandUtils::StringTrimAll(string& input, char c) {
		input.erase(std::remove(input.begin(), input.end(), c),input.end());
	}

	string BriandUtils::ipv4ToString(const in_addr& ip) {
		return string(ip4addr_ntoa( reinterpret_cast<const ip4_addr_t*>(&ip) ));
	}

	in_addr BriandUtils::ipv4FromString(const string& ip) {
		in_addr temp;
		bzero(&temp, sizeof(temp));
		ip4addr_aton(ip.c_str(), reinterpret_cast<ip4_addr_t*>(&temp));

		return temp;
	}
}
