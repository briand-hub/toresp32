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
#include <vector>

#include <lwip/inet.h>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"

using namespace std;

namespace Briand
{
	/* This class contains support functions used in code */
	class BriandUtils {
		public:

		/**
		 * Get a random byte based on ESP32 hw
		 * @return Random byte
		*/
		static unsigned char GetRandomByte();

		/**
		 * Get a random MAC Address
		 * @return Random MAC, format unsigned 
		*/
		static unique_ptr<unsigned char[]> GetRandomMAC();

		/**
		 * Get a random Hostname
		 * @return Random host name (ASCII alphanumeric chars)
		*/
		static unique_ptr<char[]> GetRandomHostName();

		/**
		 * Get a random Hostname
		 * @return Random host name (ASCII alphanumeric chars)
		*/
		static unique_ptr<char[]> GetRandomSSID();

		/**
		 * Get a random Password of specified length
		 * @param length Password length
		 * @return Random password
		*/
		static unique_ptr<char[]> GetRandomPassword(int length);

		/**
		 * Convert flags to string with specified separator
		 * @param flagMask Mask of flags
		 * @param prepend Prepend this string to output flag
		 * @param separator Output separator
		 * @return flag string list separated by separator
		*/
		static string BriandTorRelayFlagsToString(unsigned short flagMask, const string& prepend = "", const string& separator=" ");

		/**
		 * Method to query ifconfig.me and obtain headers/ip info
		 * @return string with main informations, empty if fails
		*/
		static string BriandIfConfigMe();

		/**
		 * Method to get public IP address from ifconfig.me
		 * @return string with IP, empty if fails
		*/
		static string BriandGetPublicIPFromIfConfigMe();

		/**
		 * DEBUG Method to print raw bytes to serial output (hex format)
		 * @param buffer the buffer to be printed (vector)
		 * @param bytesToPrint number of buffer bytes to print (0 to print all)
		 * @param newLineAfterBytes print a new line after N bytes (0 to print all, default)
		*/
		static void PrintByteBuffer(const vector<unsigned char>& buffer, const short& newLineAfterBytes = 0, const unsigned int& bytesToPrint = 0);

		/**
		 * DEBUG Method to print raw bytes to serial output (hex format)
		 * @param buffer the buffer to be printed (unsigned char[])
		 * @param size the buffer size
		 * @param bytesToPrint number of buffer bytes to print (0 to print all, default)
		 * @param newLineAfterBytes print a new line after N bytes (0 to print all, default)
		*/
		static void PrintOldStyleByteBuffer(unsigned char buffer[], const unsigned int& size, const short& newLineAfterBytes = 0, const unsigned int& bytesToPrint = 0);

		/**
		 * Convert a command to a readable string
		 * @param command Cell command 
		 * @return string of command
		*/
		static string BriandTorCellCommandToString(const Briand::BriandTorCellCommand& command);

		/**
		 * Convert a RELAY command to a readable string
		 * @param command Relay Cell command 
		 * @return string of command
		*/
		static string BriandTorRelayCellCommandToString(const Briand::BriandTorCellRelayCommand& command);

		/**
		 * Method return a pointer to an old-style buffer, initialized all to zero
		 * @param size The buffer size
		 * @return Pointer to buffer 
		*/
		static unique_ptr<unsigned char[]> GetOneOldBuffer(const unsigned int& size);

		/**
		 * Method to get UNIX time from ESP32
		*/
		static unsigned long GetUnixTime();

		/**
		 * Helper method convert vector to old-style buffer for libraries that needs it.
		 * SIZE IS THE SAME AS INPUT VECTOR
		 * @param input Pointer to the vector
		 * @return Pointer to buffer
		*/
		static unique_ptr<unsigned char[]> VectorToArray(const unique_ptr<vector<unsigned char>>& input);

		/**
		 * Helper method convert old-style buffer for libraries that needs it to vector
		 * @param input Pointer to buffer 
		 * @param size Buffer size
		 * @return Pointer to vector
		*/
		static unique_ptr<vector<unsigned char>> ArrayToVector(const unique_ptr<unsigned char[]>& input, const unsigned long int& size);

		/**
		 * Helper method convert string to old-style buffer for libraries that needs it.
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param input The string
		 * @param nullterminate If true, adds a null-terminate char 0x00
		 * @return Pointer to buffer
		*/
		static unique_ptr<unsigned char[]> StringToOldBuffer(const string& input, bool nullterminate = false);

		/**
		 * Helper method convert old-style buffer for libraries that needs it to string (do not include any null-terminate!)
		 * @param input The string
		 * @param size The buffer size
		 * @return The string
		*/
		static string OldBufferToString(unique_ptr<unsigned char[]>& input, const unsigned long int& size);

		/**
		 * Helper method convert an "hex" string to a vector<unsigned char>
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param hexstring The string (must be a valid hex string), each hex value must occupy 2 chars
		 * @param preNonHex Prepend this string with a non-hex format (char to raw bytes)
		 * @return Pointer to vector (empty vector if input string not even size)
		*/
		static unique_ptr<vector<unsigned char>> HexStringToVector(const string& hexstring, const string& preNonHex);

		/**
		 * Helper method convert an "hex" string to an unsigned char buffer
		 * SIZE IS THE SAME AS INPUT STRING
		 * @param hexstring The string (must be a valid hex string), each hex value must occupy 2 chars
		 * @param preNonHex Prepend this string with a non-hex format (raw char to bytes)
		 * @return Pointer to buffer (all null if input string not even size)
		*/
		static unique_ptr<unsigned char[]> HexStringToOldBuffer(const string& hexstring, unsigned int& size, const string& preNonhex, bool nullterm = false);

		/**
		 * Prints file contents to serial output 
		*/
		static void PrintFileContent(const string& filename);

		/**
		 * Method removes all occurence of a char from string
		*/
		static void StringTrimAll(string& input, char c);

		/**
		 * Converts an IPv4 in_addr struct to readable format
		 * @param ip in_addr (unsigned int) IP
		 * @return IPv4 in string format (123.456.789.000)
		*/
		static string ipv4ToString(const in_addr& ip);

		/**
		 * Converts an IPv4 readable format to an in_addr struct
		 * @param IPv4 in string format (123.456.789.000)
		 * @return IPv4 in_addr (unsigned int) IP
		*/
		static in_addr ipv4FromString(const string& ip);
	};
}
