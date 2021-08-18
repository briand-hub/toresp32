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

#include "BriandDefines.hxx"

/* This file contains static class to perform network communications */

using namespace std;

namespace Briand
{
	/** This class has members to manage the Network request/response and utility methods */
	class BriandNet {
		public:

		/**
		 * Method to convert a string to a vector<unsigned char> pointer
		 * @param input pointer to input string
		 * @param emptyContents set it to true if you want the input buffer empty after request. false to keep it.
		 * @return vector<unsigned char> pointer containing the string contents
		*/
		static unique_ptr<vector<unsigned char>> StringToUnsignedCharVector(unique_ptr<string>& input, bool emptyContents = true);

		/**
		 * Method to convert a string to a vector<unsigned char> pointer
		 * @param vector<unsigned char> pointer containing the contents 
		 * @param emptyContents set it to true if you want the input buffer empty after request. false to keep it.
		 * @return Pointer to the output string
		*/
		static unique_ptr<string> UnsignedCharVectorToString(unique_ptr<vector<unsigned char>>& input, bool emptyContents = true);

		/**
		 * Method send raw bytes to specified host using BriandIDFSocketClient and returns raw response bytes.
		 * @param host Hostname / IP
		 * @param port Port
		 * @param content Request (raw bytes) to send (c++ vector must be used)
		 * @param emptyContents set it to true if you want the input buffer empty after request. false to keep it.
		 * @return an unique_ptr to the response buffer (c++ vector), empty vector if fails
		*/
		static unique_ptr<vector<unsigned char>> RawInsecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents = true);

		/**
		 * Method send raw bytes to specified host using yout own connected and ready to go BriandIDFSocketTlsClient, returns raw response bytes. 
		 * The client must be setup with certificates if validation is wanted.
		 * @param client Pointer to your own initialized BriandIDFSocketTlsClient, connected and ready.
		 * @param content Request (raw bytes) to send (c++ vector must be used)
		 * @param emptyContents set it to true if you want the input buffer empty after request. false to keep it.
		 * @param closeConnection set it to true if you want close the connection (client->end).
		 * @param expectResponse set it to false if a response is not expected.
		 * @return an unique_ptr to the response buffer (c++ vector), empty vector if fails or response is not expected.
		*/
		static unique_ptr<vector<unsigned char>> RawSecureRequest(const unique_ptr<BriandIDFSocketTlsClient>& client, unique_ptr<vector<unsigned char>>& content, bool emptyContents = true, bool closeConnection = false, bool expectResponse = true);

		/**
		 * Method send raw bytes to specified host using BriandIDFSocketTlsClient and returns raw response bytes.
		 * @param host Hostname / IP
		 * @param port Port
		 * @param content Request (raw bytes) to send (c++ vector must be used)
		 * @param emptyContents set it to true if you want the input buffer empty after request. false to keep it.
		 * @param pemCAcert The PEM-format certificate CA root. If nullptr, INSECURE mode will be used (unless DER certificate furnished)
		 * @param derCAcert The DER-format certificate CA root. If nullptr, INSECURE mode will be used (unless PEM certificate furnished)
		 * @return an unique_ptr to the response buffer (c++ vector), empty vector if fails
		*/
		static unique_ptr<vector<unsigned char>> RawSecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents = true, const unique_ptr<string>& pemCAcert = nullptr, const unique_ptr<vector<unsigned char>>& derCAcert = nullptr);

		/**
		 * Method send an HttpS request and returns contents in string format
		 * @param host Hostname/IP (ex. ifconfig.me)
		 * @param port Port (ex. 443)
		 * @param path URI path, starting with / (ex. /all.json , /do?search=query) must be URL ENCODED before!
		 * @param httpReturnCode if success HTTP code (200/404/500..) if fails 0
		 * @param agent User-Agent to set in the header
		 * @param returnBodyOnly If true just body, without headers, is returned
		 * @param pemCAcert The PEM-format certificate CA root. If nullptr, INSECURE mode will be used (unless DER certificate furnished)
		 * @param derCAcert The DER-format certificate CA root. If nullptr, INSECURE mode will be used (unless PEM certificate furnished)
		 * @return Response string pointer, nullptr if fails
		*/
		static unique_ptr<string> HttpsGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent = "empty", const bool& returnBodyOnly = false, const unique_ptr<string>& pemCAcert = nullptr, const unique_ptr<vector<unsigned char>>& derCAcert = nullptr);

		/**
		 * Method send an Http (NOT HTTPS!) request and returns contents in string format
		 * @param host Hostname/IP (ex. ifconfig.me)
		 * @param port Port (ex. 443)
		 * @param path URI path, starting with / (ex. /all.json , /do?search=query) must be URL ENCODED before!
		 * @param httpReturnCode if success HTTP code (200/404/500..) if fails 0
		 * @param agent User-Agent to set in the header
		 * @param returnBodyOnly If true just body, without headers, is returned
		 * @return Response string pointer, nullptr if fails
		*/
		static unique_ptr<string> HttpInsecureGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent = "empty", const bool& returnBodyOnly = false);
	};
}