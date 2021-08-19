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

#include "BriandDefines.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand
{
	/* Configuration file name */
	constexpr const char* TORESP32_CONFIG_FILE_NAME = "/spiffs/torespconfig";

	/**
	 * Class to handle configuration file
	 * If encrypted must be decrypted providing key (AES128 CTR)
	 * Each line is one information and ends with \r\n
	 * line 1: contains wifi ESSID
	 * line 2: contains wifi PASSWORD
	 * line 3: serial encryption PASSWORD (empty if none) 
	*/ 
	class BriandTorEsp32Config {
		private:

		string enc_key;

		public:

		static const char* LOGTAG;

		unique_ptr<unsigned char[]> Encrypt(const string& input) {
			constexpr unsigned short BLOCK_SIZE_BYTES = 16;
			
			unsigned int INPUT_SIZE = input.length();
			unsigned char iv[BLOCK_SIZE_BYTES] = { 0x00 };			// zero-init IV
			size_t nonce_size = 0;
			unsigned char nonce_counter[BLOCK_SIZE_BYTES] = { 0x00 };
			auto outBuffer = make_unique<unsigned char[]>(INPUT_SIZE);

			esp_aes_context aes_context;

			// Init AES
			esp_aes_init(&aes_context);
			
			// Set ENC key, first param context pointer, second the key, third the key-len in BITS
			esp_aes_setkey(&aes_context, reinterpret_cast<const unsigned char*>(this->enc_key.c_str()), this->enc_key.length() * 8);
			
			// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
			esp_aes_crypt_ctr(&aes_context, INPUT_SIZE, &nonce_size, nonce_counter, iv, reinterpret_cast<const unsigned char*>(input.c_str()), outBuffer.get());

			// Free context
			esp_aes_free(&aes_context);

			return outBuffer;
		}

		string Decrypt(unique_ptr<vector<unsigned char>>& input) {
			constexpr unsigned short BLOCK_SIZE_BYTES = 16;
			
			unsigned char iv[BLOCK_SIZE_BYTES] = { 0x00 };			// zero-init IV
			size_t nonce_size = 0;
			unsigned char nonce_counter[BLOCK_SIZE_BYTES] = { 0x00 };
			auto outBuffer = make_unique<unsigned char[]>(input->size());

			string output("");

			esp_aes_context aes_context;

			// Init AES
			esp_aes_init(&aes_context);
			
			// Set ENC key, first param context pointer, second the key, third the key-len in BITS
			esp_aes_setkey(&aes_context, reinterpret_cast<const unsigned char*>(this->enc_key.c_str()), this->enc_key.length() * 8);

			// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
			esp_aes_crypt_ctr(&aes_context, input->size(), &nonce_size, nonce_counter, iv, input->data(), outBuffer.get());

			// Free context
			esp_aes_free(&aes_context);

			output.resize(input->size());
			for (int i=0; i<input->size(); i++) {
				output.at(i) = static_cast<char>( outBuffer[i] );
			}

			return output;
		}

		string WESSID;
		string WPASSWORD;
		string SERIAL_ENC_KEY;

		/**
		 * Constructor, you must take care of encryptionKey exactly 16 char long!
		*/
		BriandTorEsp32Config(string& encriptionKey) {
			this->enc_key = string("");
			this->enc_key.append(encriptionKey);
			this->WESSID = string("");
			this->WPASSWORD = string("");
			this->SERIAL_ENC_KEY = string("");
		}

		~BriandTorEsp32Config() {
			this->enc_key.resize(1);
			this->WPASSWORD.resize(1);
			this->SERIAL_ENC_KEY.resize(1);
		}

		/**
		 * Check if exists a configuration file
		 * @return true if exists
		*/
		static bool ExistConfig() {
			ifstream file(TORESP32_CONFIG_FILE_NAME, ios::in);
			bool exists = file.good();
			file.close();

			return exists;
		}

		/**
		 * Reads configuration file
		 * @return true if OK
		*/
		bool ReadConfig() {
			if (!BriandTorEsp32Config::ExistConfig()) {
				return false;
			}
			else {
				ifstream f(TORESP32_CONFIG_FILE_NAME, ios::in | ios::binary);

				auto buffer = make_unique<vector<unsigned char>>();

				while (f.good()) {
					buffer->push_back(f.get());
				}
				f.close();

				string contents = this->Decrypt(buffer);

				size_t pos;

				ESP_LOGD(LOGTAG, "\n[DEBUG] File decrypted. Contents:");

				// First line => Essid
				pos = contents.find("\r\n");
				if (pos == string::npos) return false;
				this->WESSID = contents.substr(0, pos);
				contents.erase(0, pos + 2);
				ESP_LOGD(LOGTAG, "[DEBUG] Essid: %s\n", this->WESSID.c_str());

				// Second line => Password
				pos = contents.find("\r\n");
				if (pos == string::npos) return false;
				this->WPASSWORD = contents.substr(0, pos);
				contents.erase(0, pos + 2);
				ESP_LOGD(LOGTAG, "[DEBUG] Password: %s\n", this->WPASSWORD.c_str());

				// 3rd line => Serial encryption password (could be empty)
				pos = contents.find("\r\n");
				if (pos == string::npos) return false;
				this->SERIAL_ENC_KEY = contents.substr(0, pos);
				if (this->SERIAL_ENC_KEY.length() < 16)
					this->SERIAL_ENC_KEY.clear();
				contents.erase(0, pos + 2);
				ESP_LOGD(LOGTAG, "[DEBUG] Enc KEY: %s\n", this->SERIAL_ENC_KEY.c_str());

				return true;
			}
		}

		/**
		 * Writes configuration file
		*/
		void WriteConfig() {
			string contents("");
			contents.append(this->WESSID);
			contents.append("\r\n");
						
			contents.append(this->WPASSWORD);
			contents.append("\r\n");

			if (this->SERIAL_ENC_KEY.length() < 16)
				contents.append("*\r\n"); 
			else { 
				contents.append(this->SERIAL_ENC_KEY);
				contents.append("\r\n");
			}

			auto buffer = this->Encrypt(contents);

			ofstream f(TORESP32_CONFIG_FILE_NAME, ios::out | ios::binary);

			for (int i=0; i<contents.length(); i++) {
				f.put(buffer[i]);
			}

			f.flush();
			f.close();
		}

		/**
		 * Removes the configuration file (format)
		 * maybe in future wiping?
		*/
		void DestroyConfig() {
			std::remove(TORESP32_CONFIG_FILE_NAME);
		}
	};

	const char* BriandTorEsp32Config::LOGTAG = "briandconfig";
}