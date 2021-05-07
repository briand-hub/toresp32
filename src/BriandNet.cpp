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

#include "BriandNet.hxx"

#include <cJSON.h>

#include <BriandIDFClients.hxx>

#include <iostream>
#include <memory>
#include <vector>

using namespace std;

namespace Briand
{

	unique_ptr<vector<unsigned char>> BriandNet::StringToUnsignedCharVector(unique_ptr<string>& input, bool emptyContents /* = true*/) {
		auto output = make_unique<vector<unsigned char>>();

		if (emptyContents) {
			while (input->length() > 0) {
				output->push_back( input->at(0) );
				input->erase(input->begin());
			}
		}
		else {
			for (int i=0; i<input->length(); i++) {
				output->push_back( static_cast<unsigned char>(input->at(i)) );
			}
		}
		
		return output;
	}

	unique_ptr<string> BriandNet::UnsignedCharVectorToString(unique_ptr<vector<unsigned char>>& input, bool emptyContents /* = true*/) {
		auto output = make_unique<string>();

		if (emptyContents) {
			while (input->size() > 0) {
				output->push_back( input->at(0) );
				input->erase(input->begin());
			}
		}
		else {
			for (int i=0; i<input->size(); i++) {
				output->push_back( input->at(i) );
			}
		}
		
		return output;
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawInsecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/) {
		auto output = make_unique<vector<unsigned char>>();

		auto client = make_unique<BriandIDFSocketClient>();

		// Set parameters
		client->SetVerbose(DEBUG);
		client->SetTimeout(NET_REQUEST_TIMEOUT_S);

		// Connect
		if ( !client->Connect(host.c_str(), port) ) {
			if (VERBOSE) printf("[ERR] Failed to connect\n");
			return output;
		}

		if (DEBUG) printf("[DEBUG] Connected.\n");

		// Write request
		if ( !client->WriteData(content) ) {
			if (VERBOSE) printf("[ERR] Failed to send data\n");
			return output;
		}

		if (emptyContents)
			content->clear();

		// Wait response until timeout reached
		
		if (DEBUG) printf("[DEBUG] Request sent.\n");
		if (DEBUG) printf("[DEBUG] Waiting response");

		// Response
		output = client->ReadData(false);
		
		if (DEBUG) printf("[DEBUG] Got response of %lu bytes.\n", output->size());

		client->Disconnect();

		client.reset(); // Release now please, I need RAM!

		return std::move(output);
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawSecureRequest(unique_ptr<BriandIDFSocketTlsClient>& client, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/, bool closeConnection /* = false*/, bool expectResponse /* = true */) {
		auto output = make_unique<vector<unsigned char>>();

		// Write request
		if (emptyContents) {
			while (content->size() > 0) {
				client->write( content->at(0) );
				content->erase(content->begin());
			}
		}
		else {
			for (unsigned long int i = 0; i<content->size(); i++ ) {
				client->write( content->at(i) );
			}
		}
		
		client->flush();

		// If response expected
		if (expectResponse) {
			// Wait response until timeout reached
			
			if (DEBUG) printf("[DEBUG] Request sent.\n");
			if (DEBUG) printf("[DEBUG] Waiting response");

			unsigned long startedOn = millis();
			bool timeout = false;

			while (client->available() == 0 && !timeout) {
				delay(100);
				timeout = ( millis() - startedOn ) >= NET_REQUEST_TIMEOUT_S*1000;
				if (DEBUG) printf(".");
			}
			if (DEBUG) printf("\n");

			if (timeout) {
				if (VERBOSE) printf("[ERR] Request has timed out.\n");
				return output;
			} 

			// Response ready!

			// WARNING: DO NOT USE condition isConnected() in this while, otherwise reponse truncate happens!!!!
			while (client->available() > 0) {
				output->push_back( static_cast<unsigned char>( client->read() ) );
			}
			
			if (DEBUG) printf("[DEBUG] Got response of %lu bytes.\n", output->size());

			if (client->connected() && closeConnection)
				client->stop();
		}

		return std::move(output);
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawSecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/) {
		auto output = make_unique<vector<unsigned char>>();

		auto client = make_unique<BriandIDFSocketTlsClient>();

		// TODO : find a way to validate requests.
		// Not providing a CACert will be a leak of security but hard-coding has disadvantages...

		client->setInsecure();

		// Connect

		if ( !client->connect(host.c_str(), port) ) {
			if (VERBOSE) printf("[ERR] Failed to connect\n");
			return output;
		}

		if (DEBUG) printf("[DEBUG] Connected.\n");

		// Write request

		if (emptyContents) {
			while (content->size() > 0) {
				client->write( content->at(0) );
				content->erase(content->begin());
			}
		}
		else {
			for (unsigned long int i = 0; i<content->size(); i++ ) {
				client->write( content->at(i) );
			}
		}
		
		client->flush();

		// Wait response until timeout reached
		
		if (DEBUG) printf("[DEBUG] Request sent.\n");
		if (DEBUG) printf("[DEBUG] Waiting response");

		unsigned long startedOn = millis();
		bool timeout = false;

		while (client->available() == 0 && !timeout) {
			delay(100);
			timeout = ( millis() - startedOn ) >= NET_REQUEST_TIMEOUT_S*1000;
			if (DEBUG) printf(".");
		}
		if (DEBUG) printf("\n");

		if (timeout) {
			if (VERBOSE) printf("[ERR] Request has timed out.\n");
			client.reset();
			return output;
		} 

		// Response ready!

		while (client->connected() && client->available() > 0) {
			output->push_back( static_cast<unsigned char>( client->read() ) );
		}
		
		if (DEBUG) printf("[DEBUG] Got response of %lu bytes.\n", output->size());

		if (client->connected())
			client->stop();

		client.reset(); // Release now please, I need RAM!

		return std::move(output);
	}

	unique_ptr<string> BriandNet::HttpsGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent /* = "empty"*/, const bool& returnBodyOnly /* = false*/) {
		if (DEBUG) printf("[DEBUG] HttpsGet called to https://%s:%d%s\n", host.c_str(), port, path.c_str());

		// Prepare request

		auto request = make_unique<string>();
		request->append("GET " + path + " HTTP/1.1\r\n");
		request->append("Host: " + host + "\r\n");
		request->append("User-Agent: " + agent);
		request->append("\r\n");
		request->append("Connection: close\r\n");
		request->append("\r\n");

		auto contents = StringToUnsignedCharVector(request, true);
		
		if (DEBUG) printf("[DEBUG] HttpsGet sending raw request.\n");
		auto response = RawSecureRequest(host, port, contents, true);

		if (response->size() > 0) {
			// Success
			if (DEBUG) printf("[DEBUG] HttpsGet success.\n");

			// Convert to string
			auto responseContent = UnsignedCharVectorToString(response, true);

			// Parse header to get httpCode
			// HTTP/1.1 XXX OK
			// 3 digit after space
			httpReturnCode = stoi( responseContent->substr(responseContent->find(" ") + 1, 3 ) );

			if (returnBodyOnly) {
				// Get the body without headers
				// from double \r\n to the end
				responseContent->erase(0, responseContent->find("\r\n\r\n")+4 );
			}
			
			return responseContent;
		}
		else {
			if (DEBUG) printf("[DEBUG] HttpsGet failed.\n");
			return nullptr;
		}
	}

	cJSON* BriandNet::HttpsGetJson(const string& host, const short& port, const string& path, short& httpReturnCode, bool& deserializationSuccess, const string& agent  /* = "empty"*/, const unsigned int& expectedSize /* = 1024*/) {
		if (DEBUG) printf("[DEBUG] HttpsGetJson called to https://%s:%d/%s\n", host.c_str(), port, path.c_str());
		
		deserializationSuccess = false;

		auto response = HttpsGet(host, port, path, httpReturnCode, agent, true);

		if (httpReturnCode == 200) {
			if (DEBUG) printf("[DEBUG] HttpsGetJson response ok (200).\n");

			// Seems that sometimes additional bytes are included in response when body only is requested. 
			// So remove before the first { and after the last }

			auto fpos = response->find("{");
			auto lpos = response->find_last_of("}");

			if (fpos != std::string::npos) response->erase(response->begin(), response->begin() + fpos);
			if (lpos != std::string::npos) response->erase(response->begin() + lpos + 1, response->end());

			DynamicJsonDocument doc( expectedSize ); 
			DeserializationError err = deserializeJson(doc, response->c_str());

			if (err) {
				if (DEBUG) printf("[DEBUG] HttpsGetJson deserialization failed: %s\n", err.c_str());
				deserializationSuccess = false;
			}
			else {
				if (DEBUG) printf("[DEBUG] HttpsGetJson deserialization ok.\n");	
				deserializationSuccess = true;
			}

			doc.shrinkToFit();
			return doc;
		}
		else {
			if (DEBUG) printf("[DEBUG] HttpsGetJson failed httpcode = %d\n ", httpReturnCode);
			return DynamicJsonDocument(1); // Just one byte 
		}
	}

	unique_ptr<string> BriandNet::HttpInsecureGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent /* = "empty"*/, const bool& returnBodyOnly /* = false*/) {
		if (DEBUG) printf("[DEBUG] HttpInsecureGet called to http://%s:%d%s\n", host.c_str(), port, path.c_str());

		// Prepare request

		auto request = make_unique<string>();
		request->append("GET " + path + " HTTP/1.1\r\n");
		request->append("Host: " + host + "\r\n");
		request->append("User-Agent: " + agent);
		request->append("\r\n");
		request->append("Connection: close\r\n");
		request->append("\r\n");

		auto contents = StringToUnsignedCharVector(request, true);
		
		if (DEBUG) printf("[DEBUG] HttpInsecureGet sending raw request.\n");
		auto response = RawInsecureRequest(host, port, contents, true);

		if (response->size() > 0) {
			// Success
			if (DEBUG) printf("[DEBUG] HttpInsecureGet success.\n");

			// Convert to string
			auto responseContent = UnsignedCharVectorToString(response, true);

			// Parse header to get httpCode
			// HTTP/1.1 XXX OK
			// 3 digit after space
			httpReturnCode = stoi( responseContent->substr(responseContent->find(" ") + 1, 3 ) );

			if (returnBodyOnly) {
				// Get the body without headers
				// from double \r\n to the end
				responseContent->erase(0, responseContent->find("\r\n\r\n")+4 );
			}
			
			return responseContent;
		}
		else {
			if (DEBUG) printf("[DEBUG] HttpInsecureGet failed.\n");
			return nullptr;
		}
	}

}