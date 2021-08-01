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

using namespace std;

namespace Briand {
	class BriandTorAes {
		private:
		const unsigned short AES_BLOCK_SIZE_BYTES = 16;

		public:

		static string aes_encrypt(const string& input, const string& key) {
			constexpr unsigned short BLOCK_SIZE_BYTES = 16;
			
			unsigned char iv[BLOCK_SIZE_BYTES] = { 0x00 };			// zero-init IV
			size_t nonce_size = 0;
			unsigned char nonce_counter[BLOCK_SIZE_BYTES] = { 0x00 };
			unsigned char outBuffer[input.length()] = { 0x00 }; 

			string output("");

			// Key size check (16 AES128 / 32 AES256)
			// ... TODO

			mbedtls_aes_context aes_context;

			// Init AES
			mbedtls_aes_init(&aes_context);
			

			// Set ENC key, first param context pointer, second the key, third the key-len in BITS
			mbedtls_aes_setkey_enc(&aes_context, reinterpret_cast<const unsigned char*>(key.c_str()), key.length() * 8);

			// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
			mbedtls_aes_crypt_ctr(&aes_context, input.length(), &nonce_size, nonce_counter, iv, reinterpret_cast<const unsigned char*>(input.c_str()), outBuffer);

			// Free context
			mbedtls_aes_free(&aes_context);

			output.resize(input.length());
			for (int i=0; i<input.length(); i++) {
				output[i] = outBuffer[i];
			}

			return output;
		}

		static string aes_decrypt(const string& input, const string& key) {
			constexpr unsigned short BLOCK_SIZE_BYTES = 16;
			
			unsigned char iv[BLOCK_SIZE_BYTES] = { 0x00 };			// zero-init IV
			size_t nonce_size = 0;
			unsigned char nonce_counter[BLOCK_SIZE_BYTES] = { 0x00 };
			unsigned char outBuffer[input.length()] = { 0x00 }; 

			string output("");

			// Key size check (16 AES128 / 32 AES256)
			// ... TODO

			mbedtls_aes_context aes_context;

			// Init AES
			mbedtls_aes_init(&aes_context);

			// Set ENC key, first param context pointer, second the key, third the key-len in BITS
			mbedtls_aes_setkey_dec(&aes_context, reinterpret_cast<const unsigned char*>(key.c_str()), key.length() * 8);

			// Encrypt (only CBC mode makes 16-bytes per round, CTR has not this problem with input)
			mbedtls_aes_crypt_ctr(&aes_context, input.length(), &nonce_size, nonce_counter, iv, reinterpret_cast<const unsigned char*>(input.c_str()), outBuffer);

			// Free context
			mbedtls_aes_free(&aes_context);

			output.resize(input.length());
			for (int i=0; i<input.length(); i++) {
				output[i] = outBuffer[i];
			}

			return output;
		}

		static string stringToHex(const string& input) {
			ostringstream s;
			s << "0x ";
			for (int i=0; i<input.length(); i++) {
				s << hex << static_cast<unsigned short>(input.at(i)) << " ";
			}
			return s.str();
		}
	};
}
