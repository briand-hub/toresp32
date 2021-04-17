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
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

#include <ArduinoJson.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"


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
			// prepare output
			string output("");

			auto clientHttp = make_unique<HTTPClient>();
			DynamicJsonDocument doc(512); // Should be enough for data and safe for RAM...

			// Not providing a CACert will be a leak of security but hard-coding has disadvantages...	
			clientHttp->begin( "https://ifconfig.me/all.json" );
			int httpCode = clientHttp->GET();

			if (httpCode == 200) {
				// It is safe RAM beacause request just little data with poor fields,
				// thus RAM should be fine...
								
				string responseContent = string( clientHttp->getString().c_str() );
				clientHttp->end();
				clientHttp.reset(); // now please, I need RAM!

				if (DEBUG) Serial.printf("[DEBUG] Got response HTTP/200\n");
				if (DEBUG) Serial.printf("[DEBUG] Raw response of %d bytes: %s\n", responseContent.length(), responseContent.c_str() );

				DeserializationError err = deserializeJson(doc, responseContent.c_str());
				
				if (err) {
					Serial.printf("[ERR] Error on deserialization from https://ifconfig.me/all.json\n");
				}
				else {
					if (DEBUG) Serial.printf("[DEBUG] Json document allocated %d bytes\n", doc.memoryUsage());
					doc.shrinkToFit();
					if (DEBUG) Serial.printf("[DEBUG] Json document shrink to %d bytes.\n", doc.memoryUsage());

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

					responseContent.clear();
				}
			}
			else
				Serial.printf("[ERR] Error on downloading from https://ifconfig.me/all.json Http code: %d\n", httpCode);

			return output;
		}

		/**
		 * Method to print raw bytes to serial (hex format)
		 * @param buffer the buffer to be printed
		 * @param length the buffer size
		*/
		static void printByteBuffer(const unsigned char* buffer, const unsigned int& length) {
			for (unsigned int i=0; i < length; i++) {
				Serial.printf("%02X ", buffer[i]);
			}
			Serial.print("\n");
		}

		/**
		 * Method to print raw bytes to serial (hex format)
		 * @param buffer the buffer to be printed (vector)
		*/
		static void printByteBuffer(vector<unsigned char>& buffer) {
			for (unsigned int i=0; i < buffer.size(); i++) {
				Serial.printf("%02X ", buffer.at(i));
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
	};
	
}
