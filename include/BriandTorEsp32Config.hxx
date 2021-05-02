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

#include <Arduino.h>
#include <FS.h>
#include <SPIFFS.h>
#include <iostream>
#include <memory>

// HW Accelleration by ESP32 cryptographic hardware
#include <mbedtls/aes.h>

#include "BriandDefines.hxx"

using namespace std;

namespace Briand
{
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

		unique_ptr<unsigned char[]> encrypt(const string& input) {
			constexpr unsigned short BLOCK_SIZE_BYTES = 16;
			
			unsigned int INPUT_SIZE = input.length();
			unsigned char iv[BLOCK_SIZE_BYTES] = { 0x00 };			// zero-init IV
			size_t nonce_size = 0;
			unsigned char nonce_counter[BLOCK_SIZE_BYTES] = { 0x00 };
			auto outBuffer = make_unique<unsigned char[]>(INPUT_SIZE);

			mbedtls_aes_context aes_context;

			// Init AES
			mbedtls_aes_init(&aes_context);
			
			// Set ENC key, first param context pointer, second the key, third the key-len in BITS
			mbedtls_aes_setkey_enc(&aes_context, reinterpret_cast<const unsigned char*>(this->enc_key.c_str()), this->enc_key.length() * 8);
			
			// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
			mbedtls_aes_crypt_ctr(&aes_context, INPUT_SIZE, &nonce_size, nonce_counter, iv, reinterpret_cast<const unsigned char*>(input.c_str()), outBuffer.get());

			// Free context
			mbedtls_aes_free(&aes_context);

			return outBuffer;
		}

		string decrypt(unique_ptr<unsigned char[]>& input, unsigned int inputSizeBytes) {
			constexpr unsigned short BLOCK_SIZE_BYTES = 16;
			
			unsigned char iv[BLOCK_SIZE_BYTES] = { 0x00 };			// zero-init IV
			size_t nonce_size = 0;
			unsigned char nonce_counter[BLOCK_SIZE_BYTES] = { 0x00 };
			auto outBuffer = make_unique<unsigned char[]>(inputSizeBytes);

			string output("");

			mbedtls_aes_context aes_context;

			// Init AES
			mbedtls_aes_init(&aes_context);

			// Set ENC key, first param context pointer, second the key, third the key-len in BITS
			mbedtls_aes_setkey_dec(&aes_context, reinterpret_cast<const unsigned char*>(this->enc_key.c_str()), this->enc_key.length() * 8);

			// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
			mbedtls_aes_crypt_ctr(&aes_context, inputSizeBytes, &nonce_size, nonce_counter, iv, (input.get()), outBuffer.get());

			// Free context
			mbedtls_aes_free(&aes_context);

			output.resize(inputSizeBytes);
			for (int i=0; i<inputSizeBytes; i++) {
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
		static bool existConfig() {
			if (!SPIFFS.exists("/torespconfig"))
				return false;

			return true;
		}

		/**
		 * Reads configuration file
		 * @return true if OK
		*/
		bool readConfig() {
			if (!SPIFFS.exists("/torespconfig")) {
				return false;
			}
			else {
				File f = SPIFFS.open("/torespconfig", "r");				

				unsigned int bytesRead = 0;
				auto buffer = make_unique<unsigned char[]>(f.size());

				while (f.available()) {
					buffer[bytesRead] = f.read();
					bytesRead++;
				}
				f.close();

				string contents = this->decrypt(buffer, bytesRead);

				unsigned int pos;

				if (DEBUG) Serial.println("\n[DEBUG] File decrypted. Contents:");

				// First line => Essid
				pos = contents.find("\r\n");
				if (pos == string::npos) return false;
				this->WESSID = contents.substr(0, pos);
				contents.erase(0, pos + 2);
				if (DEBUG) Serial.printf("[DEBUG] Essid: %s\n", this->WESSID.c_str());

				// Second line => Password
				pos = contents.find("\r\n");
				if (pos == string::npos) return false;
				this->WPASSWORD = contents.substr(0, pos);
				contents.erase(0, pos + 2);
				if (DEBUG) Serial.printf("[DEBUG] Password: %s\n", this->WPASSWORD.c_str());

				// 3rd line => Serial encryption password (could be empty)
				pos = contents.find("\r\n");
				if (pos == string::npos) return false;
				this->SERIAL_ENC_KEY = contents.substr(0, pos);
				if (this->SERIAL_ENC_KEY.length() < 16)
					this->SERIAL_ENC_KEY.clear();
				contents.erase(0, pos + 2);
				if (DEBUG) Serial.printf("[DEBUG] Enc KEY: %s\n", this->SERIAL_ENC_KEY.c_str());

				return true;
			}
		}

		/**
		 * Writes configuration file
		*/
		void writeConfig() {
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

			auto buffer = this->encrypt(contents);

			File f = SPIFFS.open("/torespconfig", "w");
			for (int i=0; i<contents.length(); i++) {
				f.write( buffer[i] );
			}

			f.flush();
			f.close();
		}

		/**
		 * Removes the configuration file (format)
		 * maybe in future wiping?
		*/
		void destroyConfig() {
			SPIFFS.remove("/torespconfig");
		}
	};
}