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
#include <random>
#include <esp_system.h>

#include <Arduino.h>
#include <WiFiClientSecure.h>

#include <ArduinoJson.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandNet.hxx"


/* This file contains support functions used in code */

using namespace std;

namespace Briand
{
	class BriandUtils {
		public:

		/**
		 * Get a random byte based on ESP32 hw
		 * @return Random byte
		*/
		static unsigned char GetRandomByte() {
			// default_random_engine generator;	
			// uniform_int_distribution<int> distribution(0x00, 0xFF); 
			// return distribution(generator);

			// return static_cast<unsigned char>( esp_random() );

			// Better implementation

			return static_cast<unsigned char>( esp_random() % 0x100 );
		}

		/**
		 * Get a random MAC Address
		 * @return Random MAC, format unsigned 
		*/
		static unique_ptr<unsigned char[]> GetRandomMAC() {
			auto mac = make_unique<unsigned char[]>(6);
			
			mac[0] = GetRandomByte();
			mac[1] = GetRandomByte();
			mac[2] = GetRandomByte();
			mac[3] = GetRandomByte();
			mac[4] = GetRandomByte();
			mac[5] = GetRandomByte();

			return mac;
		}

		/**
		 * Get a random Hostname
		 * @return Random host name (ASCII alphanumeric chars)
		*/
		static unique_ptr<char[]> GetRandomHostName() {
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

		/**
		 * Get a random Hostname
		 * @return Random host name (ASCII alphanumeric chars)
		*/
		static unique_ptr<char[]> GetRandomSSID() {
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

		/**
		 * Get a random Password of specified length
		 * @param length Password length
		 * @return Random password
		*/
		static unique_ptr<char[]> GetRandomPassword(int length) {
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
			
		/**
		 * Convert flags to string with specified separator
		 * @param flagMask Mask of flags
		 * @param prepend Prepend this string to output flag
		 * @param separator Output separator
		 * @return flag string list separated by separator
		*/
		static string BriandTorRelayFlagsToString(unsigned short flagMask, const string& prepend = "", const string& separator=" ") {
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
				output.pop_back(); // remove last separator

			return output;
		}

		/**
		 * Method to query ifconfig.me for obtain headers/ip info
		 * @return string with main informations, empty if fails
		*/
		static string BriandIfConfigMe() {
			bool success = false;
			short httpCode = 0;
			string randomAgent = string( Briand::BriandUtils::GetRandomHostName().get() );
			DynamicJsonDocument doc = Briand::BriandNet::HttpsGetJson("ifconfig.me", 443, "/all.json", httpCode, success, randomAgent, 512);

			// Prepare output
			string output("");

			if (success) {
				if (doc.containsKey("ip_addr")) {
					output.append("[IFCONFIG.me Public ip]: ");
					output.append( doc["ip_addr"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("remote_host")) {
					output.append("[IFCONFIG.me Remote host]: ");
					output.append( doc["remote_host"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("user_agent")) {
					output.append("[IFCONFIG.me User-Agent]: ");
					output.append( doc["user_agent"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("port")) {
					output.append("[IFCONFIG.me Port]: ");
					output.append( std::to_string( doc["port"].as<int>() ) );
					output.append("\n");
				}
				if (doc.containsKey("language")) {
					output.append("[IFCONFIG.me Language]: ");
					output.append( doc["language"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("encoding")) {
					output.append("[IFCONFIG.me Encoding]: ");
					output.append( doc["encoding"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("mime")) {
					output.append("[IFCONFIG.me Mime]: ");
					output.append( doc["mime"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("via")) {
					output.append("[IFCONFIG.me Via]: ");
					output.append( doc["via"].as<const char*>() );
					output.append("\n");
				}
				if (doc.containsKey("forwarded")) {
					output.append("[IFCONFIG.me Forwarded]: ");
					output.append( doc["forwarded"].as<const char*>() );
					output.append("\n");
				}
			}
			else {
				Serial.printf("[ERR] Error on downloading from https://ifconfig.me/all.json Http code: %d Deserialization success: %d\n", httpCode, success);
			}

			return output;
		}

		/**
		 * DEBUG Method to print raw bytes to serial output (hex format)
		 * @param buffer the buffer to be printed (vector)
		 * @param bytesToPrint number of buffer bytes to print (0 to print all)
		 * @param newLineAfterBytes print a new line after N bytes
		*/
		static void PrintByteBuffer(const vector<unsigned char>& buffer, const short& newLineAfterBytes = 8, const unsigned int& bytesToPrint = 0) {
			unsigned int limit;

			if (bytesToPrint > 0 && bytesToPrint < buffer.size()) limit = bytesToPrint;
			else limit = buffer.size();

			for (unsigned int i=0; i < limit; i++) {
				Serial.printf("%02X", buffer.at(i));
				if (i > 0 && i % newLineAfterBytes == 0) Serial.print("\n");
			}
			Serial.print("\n");
		}
	
		/**
		 * DEBUG Method to print raw bytes to serial output (hex format)
		 * @param buffer the buffer to be printed (unsigned char[])
		 * @param size the buffer size
		 * @param bytesToPrint number of buffer bytes to print (0 to print all)
		 * @param newLineAfterBytes print a new line after N bytes
		*/
		static void PrintOldStyleByteBuffer(unsigned char buffer[], const unsigned int& size, const short& newLineAfterBytes = 8, const unsigned int& bytesToPrint = 0) {
			unsigned int limit;

			if (bytesToPrint > 0 && bytesToPrint < size) limit = bytesToPrint;
			else limit = size;

			for (unsigned int i=0; i < limit; i++) {
				Serial.printf("%02X", buffer[i]);
				if (i > 0 && i % newLineAfterBytes == 0) Serial.print("\n");
			}
			Serial.print("\n");
		}
	
		/**
		 * Convert a command to a readable string
		 * @param command Cell command 
		*/
		static string BriandTorCellCommandToString(const Briand::BriandTorCellCommand& command) {
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
	
		/**
		 * Method return a pointer to an old-style buffer, initialized all to zero
		 * @param size The buffer size
		 * @return Pointer to buffer 
		*/
		static unique_ptr<unsigned char[]> GetOneOldBuffer(const unsigned int& size) {
			auto buf = make_unique<unsigned char[]>(size);
			// init to zero
			for (unsigned int i = 0; i<size; i++) {
				buf[i] = 0x00;
			}

			return std::move(buf);
		}

		/**
		 * Method to get UNIX time from ESP32
		*/
		static unsigned long GetUnixTime() {
			time_t now;
			time(&now);
			return now;
		}
	
		/**
		 * Helper method convert vector to old-style buffer for libraries that needs it.
		 * SIZE IS THE SAME AS INPUT VECTOR
		 * @param input Pointer to the vector
		 * @return Pointer to buffer
		*/
		static unique_ptr<unsigned char[]> VectorToArray(const unique_ptr<vector<unsigned char>>& input) {
			auto b = make_unique<unsigned char[]>(input->size());
			for (unsigned long int i = 0; i < input->size(); i++)
				b[i] = input->at(i);
			return std::move(b);
		}

		/**
		 * Helper method convert old-style buffer for libraries that needs it to vector
		 * @param input Pointer to buffer 
		 * @param size Buffer size
		 * @return Pointer to vector
		*/
		static unique_ptr<vector<unsigned char>> ArrayToVector(const unique_ptr<unsigned char[]>& input, const unsigned long int& size) {
			auto v = make_unique<vector<unsigned char>>();
			for (int i = 0; i < size; i++)
				v->push_back(input[i]);
			return std::move(v);
		}

		/**
		 * Helper method convert string to old-style buffer for libraries that needs it.
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param input The string
		 * @param nullterminate If true, adds a null-terminate char 0x00
		 * @return Pointer to buffer
		*/
		static unique_ptr<unsigned char[]> StringToOldBuffer(const string& input, bool nullterminate = false) {
			unsigned long int size = input.length();

			if (nullterminate) size++;

			auto b = make_unique<unsigned char[]>(size);
			for (unsigned long int i = 0; i < input.length(); i++)
				b[i] = input.at(i);

			return std::move(b);
		}

		/**
		 * Helper method convert old-style buffer for libraries that needs it to string (do not include any null-terminate!)
		 * @param input The string
		 * @param size The buffer size
		 * @return The string
		*/
		static string OldBufferToString(unique_ptr<unsigned char[]>& input, const unsigned long int& size) {
			string output("");
			unsigned long int limit = size;

			// If null-terminated string, do not include
			if (input[size-1] == 0x00) limit--;

			for (unsigned long int i = 0; i < limit; i++) 
				output.push_back(input[i]);
			
			return output;
		}

		/**
		 * Helper method convert string to vector.
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param input The string
		 * @return Pointer to vector
		*/
		static unique_ptr<vector<unsigned char>> StringToVector(const string& input) {
			auto v = make_unique<vector<unsigned char>>();
			for (unsigned long int i = 0; i < input.length(); i++)
				v->push_back(input.at(i));

			return std::move(v);
		}

		/**
		 * Helper method convert vector to string
		 * @param input The vector
		 * @return The string
		*/
		static string VectorToString(unique_ptr<vector<unsigned char>>& input) {
			string output("");

			for (unsigned long int i = 0; i < input->size(); i++) 
				output.push_back(input->at(i));
			
			return output;
		}

		/**
		 * Helper method convert an "hex" string to a vector<unsigned char>
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param hexstring The string (must be a valid hex string), each hex value must occupy 2 chars
		 * @param preNonHex Prepend this string with a non-hex format (char to raw bytes)
		 * @return Pointer to vector (empty vector if input string not even size)
		*/
		static unique_ptr<vector<unsigned char>> HexStringToVector(const string& hexstring, const string& preNonHex) {
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

		/**
		 * Helper method convert an "hex" string to an unsigned char buffer
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param hexstring The string (must be a valid hex string), each hex value must occupy 2 chars
		 * @param preNonHex Prepend this string with a non-hex format (raw char to bytes)
		 * @return Pointer to buffer (all null if input string not even size)
		*/
		static 	unique_ptr<unsigned char[]> HexStringToOldBuffer(const string& hexstring, unsigned int& size, const string& preNonhex, bool nullterm = false) {
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


	};
	
}
