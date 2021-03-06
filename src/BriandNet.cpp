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

using namespace std;

namespace Briand
{
	const char* BriandNet::LOGTAG = "briandnet";

	unique_ptr<vector<unsigned char>> BriandNet::StringToUnsignedCharVector(unique_ptr<string>& input, bool emptyContents /* = true*/) {
		auto output = make_unique<vector<unsigned char>>();
		output->reserve(input->size()); // allocate the right memory

		if (input == nullptr || input->size() == 0) {
			
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] StringToUnsignedCharVector called with null data!\n");
			#endif

			return output;
		} 

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
		output->reserve(input->size()); // allocate the right memory

		if (input == nullptr || input->size() == 0) {

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] UnsignedCharVectorToString called with null data!\n");
			#endif

			return output;
		} 

		if (input == nullptr)
			return output;

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

		// Resize input
		input->shrink_to_fit();
		
		return output;
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawInsecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/) {
		auto output = make_unique<vector<unsigned char>>();
		output->reserve(1024); // min. 1KB reserved

		if (content == nullptr || content->size() == 0) {
			
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] RawInsecureRequest called with null data!\n");
			#endif

			return output;
		} 

		auto client = make_unique<BriandIDFSocketClient>();

		// Set parameters
		client->SetVerbose(false);
		client->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		// Connect
		if ( !client->Connect(host.c_str(), port) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to connect\n");
			return output;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Connected.\n");
		#endif

		// Write request
		if ( !client->WriteData(content) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to send data\n");
			return output;
		}

		if (emptyContents)
			content->clear();

		// Wait response until timeout reached
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Request sent.\n");
		ESP_LOGD(LOGTAG, "[DEBUG] Waiting response");
		#endif

		// Response
		output = client->ReadData(false);
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got response of %d bytes.\n", output->size());
		#endif

		client->Disconnect();

		client.reset(); // Release now please, I need RAM!

		return std::move(output);
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawSecureRequest(const unique_ptr<BriandIDFSocketTlsClient>& client, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/, bool closeConnection /* = false*/, bool expectResponse /* = true */) {
		auto output = make_unique<vector<unsigned char>>();
		output->reserve(512); // min 512KB

		if (content == nullptr || content->size() == 0) {
			
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] RawSecureRequest called with null data!\n");
			#endif
			
			return output;
		} 

		// Write request

		client->WriteData(content);

		if (emptyContents)
			content->clear();
		
		// If response expected
		if (expectResponse) {
			// Wait response until timeout reached
			// Read response
			output = client->ReadData();
			
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Got response of %d bytes.\n", output->size());
			#endif

			if (client->IsConnected() && closeConnection)
				client->Disconnect();
		}
		
		return std::move(output);
	}

	unique_ptr<vector<unsigned char>> BriandNet::RawSecureRequest(const string& host, const short& port, unique_ptr<vector<unsigned char>>& content, bool emptyContents /* = true*/, const unique_ptr<string>& pemCAcert /*= nullptr*/, const unique_ptr<vector<unsigned char>>& derCAcert /*= nullptr*/) {
		auto output = make_unique<vector<unsigned char>>();

		if (content == nullptr || content->size() == 0) {

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] RawSecureRequest called with null data!\n");
			#endif 

			return output;
		} 

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

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Insecure mode (no PEM/DER CA certificate).\n");
			#endif

		}

		// Connect

		if ( !client->Connect(host, port) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to connect\n");
			return output;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Connected.\n");
		#endif

		// Write request
		client->WriteData(content);


		if (emptyContents)
			content->clear();

		// Wait response until timeout reached
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Request sent.\n");
		ESP_LOGD(LOGTAG, "[DEBUG] Waiting response\n");
		#endif

		// Response ready!
		output = client->ReadData();
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got response of %d bytes.\n", output->size());
		#endif

		if (client->IsConnected())
			client->Disconnect();

		client.reset(); // Release now please, I need RAM!

		return std::move(output);
	}

	unique_ptr<string> BriandNet::HttpsGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent /* = "empty"*/, const bool& returnBodyOnly /* = false*/, const unique_ptr<string>& pemCAcert /*= nullptr*/, const unique_ptr<vector<unsigned char>>& derCAcert /*= nullptr*/) {
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet called to https://%s:%d%s\n", host.c_str(), port, path.c_str());
		#endif

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
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet sending raw request.\n");
		#endif

		auto response = RawSecureRequest(host, port, contents, true, pemCAcert, derCAcert);

		if (response->size() > 0) {
			// Success

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet success.\n");
			#endif

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

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] HttpsGet failed.\n");
			#endif
			
			return nullptr;
		}
	}

	unique_ptr<string> BriandNet::HttpInsecureGet(const string& host, const short& port, const string& path, short& httpReturnCode, const string& agent /* = "empty"*/, const bool& returnBodyOnly /* = false*/) {
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet called to http://%s:%d%s\n", host.c_str(), port, path.c_str());
		#endif

		// Prepare request

		auto request = make_unique<string>();
		request->append("GET " + path + " HTTP/1.1\r\n");
		request->append("Host: " + host + "\r\n");
		request->append("User-Agent: " + agent);
		request->append("\r\n");
		request->append("Connection: close\r\n");
		request->append("\r\n");

		auto contents = StringToUnsignedCharVector(request, true);
		
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet sending raw request.\n");
		#endif
		
		auto response = RawInsecureRequest(host, port, contents, true);

		if (response->size() > 0) {
			// Success

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet success.\n");
			#endif

			// Convert to string
			auto responseContent = UnsignedCharVectorToString(response, true);

			// Parse header to get httpCode
			// HTTP/1.1 XXX OK
			// 3 digit after space
			size_t httpStatusPos = responseContent->find(" ");
			if (httpStatusPos != string::npos) {
				string httpStatusStr = responseContent->substr(httpStatusPos + 1, 3 );
				if (httpStatusStr.size() > 0)
					httpReturnCode = stoi( httpStatusStr );
			}

			if (returnBodyOnly) {
				// Get the body without headers
				// from double \r\n to the end
				responseContent->erase(0, responseContent->find("\r\n\r\n")+4 );
			}
			
			return responseContent;
		}
		else {
			
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] HttpInsecureGet failed.\n");
			#endif
			
			return nullptr;
		}
	}

}