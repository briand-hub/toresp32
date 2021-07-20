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

#include <BriandIDFSocketClient.hxx>
#include <BriandIDFSocketTlsClient.hxx>

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
		client->SetVerbose(false);
		client->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		// Connect
		if ( !client->Connect(host.c_str(), port) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to connect\n");
			return output;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Connected.\n");

		// Write request
		if ( !client->WriteData(content) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to send data\n");
			return output;
		}

		if (emptyContents)
			content->clear();

		// Wait response until timeout reached
		
		ESP_LOGD(LOGTAG, "[DEBUG] Request sent.\n");
		ESP_LOGD(LOGTAG, "[DEBUG] Waiting response");

		// Response
		output = client->ReadData(false);
		
		ESP_LOGD(LOGTAG, "[DEBUG] Got response of %d bytes.\n", output->size());

		client->Disconnect();

		client.reset(); // Release now please, I need RAM!

		return std::move(output);
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawSecureRequest(const unique_ptr<BriandIDFSocketTlsClient>& client, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/, bool closeConnection /* = false*/, bool expectResponse /* = true */) {
		auto output = make_unique<vector<unsigned char>>();

		// Write request

		client->WriteData(content);

		if (emptyContents)
			content->clear();
		
		// If response expected
		if (expectResponse) {
			// Wait response until timeout reached
			// Read response
			output = client->ReadData();
			
			ESP_LOGD(LOGTAG, "[DEBUG] Got response of %d bytes.\n", output->size());

			if (client->IsConnected() && closeConnection)
				client->Disconnect();
		}
		
		return std::move(output);
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawSecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/, const unique_ptr<string>& pemCAcert /*= nullptr*/, const unique_ptr<vector<unsigned char>>& derCAcert /*= nullptr*/) {
		auto output = make_unique<vector<unsigned char>>();

		auto client = make_unique<BriandIDFSocketTlsClient>();

		// Set parameters
		client->SetVerbose(false);
		client->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		if (pemCAcert != nullptr) {
			client->SetCACertificateChainPEM(*pemCAcert.get());
		}
		else if (derCAcert != nullptr) {
			client->AddCACertificateToChainDER(*derCAcert.get());
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] Insecure mode (no PEM/DER CA certificate).\n");
		}

		// Connect

		if ( !client->Connect(host, port) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to connect\n");
			return output;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Connected.\n");

		// Write request
		client->WriteData(content);


		if (emptyContents)
			content->clear();

		// Wait response until timeout reached
		
		ESP_LOGD(LOGTAG, "[DEBUG] Request sent.\n");
		ESP_LOGD(LOGTAG, "[DEBUG] Waiting response\n");

		// Response ready!
		output = client->ReadData();
		
		ESP_LOGD(LOGTAG, "[DEBUG] Got response of %d bytes.\n", output->size());

		if (client->IsConnected())
			client->Disconnect();

		client.reset(); // Release now please, I need RAM!

		return std::move(output);
	}

	unique_ptr<string> BriandNet::HttpsGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent /* = "empty"*/, const bool& returnBodyOnly /* = false*/, const unique_ptr<string>& pemCAcert /*= nullptr*/, const unique_ptr<vector<unsigned char>>& derCAcert /*= nullptr*/) {
		ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet called to https://%s:%d%s\n", host.c_str(), port, path.c_str());

		// Prepare request

		auto request = make_unique<string>();
		request->append("GET " + path + " HTTP/1.1\r\n");
		request->append("Host: " + host + "\r\n");
		request->append("User-Agent: " + agent);
		request->append("\r\n");
		request->append("Connection: close\r\n");
		request->append("\r\n");

		auto contents = StringToUnsignedCharVector(request, true);
		request.reset();
		
		ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet sending raw request.\n");
		auto response = RawSecureRequest(host, port, contents, true, pemCAcert, derCAcert);

		if (response->size() > 0) {
			// Success
			ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet success.\n");

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
			ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet failed.\n");
			return nullptr;
		}
	}

	cJSON* BriandNet::HttpsGetJson(const string& host, const short& port, const string& path, short& httpReturnCode, bool& deserializationSuccess, const string& agent  /* = "empty"*/, const unique_ptr<string>& pemCAcert /*= nullptr*/, const unique_ptr<vector<unsigned char>>& derCAcert /*= nullptr*/) {
		ESP_LOGD(LOGTAG, "[DEBUG] HttpsGetJson called to https://%s:%d/%s\n", host.c_str(), port, path.c_str());
		
		deserializationSuccess = false;

		auto response = HttpsGet(host, port, path, httpReturnCode, agent, true);

		if (httpReturnCode == 200) {
			ESP_LOGD(LOGTAG, "[DEBUG] HttpsGetJson response ok (200).\n");

			// Seems that sometimes additional bytes are included in response when body only is requested. 
			// So remove before the first { and after the last }

			auto fpos = response->find("{");
			auto lpos = response->find_last_of("}");

			if (fpos != std::string::npos) response->erase(response->begin(), response->begin() + fpos);
			if (lpos != std::string::npos) response->erase(response->begin() + lpos + 1, response->end());

			cJSON* root = cJSON_Parse(response->c_str());

			if (root == NULL) {
				// Get last error
				const char *error_ptr = cJSON_GetErrorPtr();
				ESP_LOGD(LOGTAG, "[DEBUG] JSON parsing error: %s\n", error_ptr);
				// Free resources
				cJSON_Delete(root);
				return NULL;
			}

			ESP_LOGD(LOGTAG, "[DEBUG] JSON deserialization success.\n");
			deserializationSuccess = true;

			return root;
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] HttpsGetJson failed httpcode = %d\n ", httpReturnCode);
			return NULL;
		}
	}

	unique_ptr<string> BriandNet::HttpInsecureGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent /* = "empty"*/, const bool& returnBodyOnly /* = false*/) {
		ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet called to http://%s:%d%s\n", host.c_str(), port, path.c_str());

		// Prepare request

		auto request = make_unique<string>();
		request->append("GET " + path + " HTTP/1.1\r\n");
		request->append("Host: " + host + "\r\n");
		request->append("User-Agent: " + agent);
		request->append("\r\n");
		request->append("Connection: close\r\n");
		request->append("\r\n");

		auto contents = StringToUnsignedCharVector(request, true);
		
		ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet sending raw request.\n");
		auto response = RawInsecureRequest(host, port, contents, true);

		if (response->size() > 0) {
			// Success
			ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet success.\n");

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
			ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet failed.\n");
			return nullptr;
		}
	}

}