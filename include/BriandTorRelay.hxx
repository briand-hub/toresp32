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

// Crypto library chosen
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <esp32/aes.h>

#include "BriandTorCertificates.hxx"

using namespace std;

namespace Briand {
	/**
	 * This class describes and keeps information about a single Tor Relay
	*/
	class BriandTorRelay {
		private:
		protected:

		public:

		unique_ptr<string> nickname;
		//unique_ptr<string> first_address;
		unique_ptr<string> address;
		unsigned short port;
		unique_ptr<string> fingerprint;
		/** @deprecated unused! */
		unique_ptr<string> effective_family;
		
		// TODO : add exit policy summary accept/reject
		// TODO: handle more fields (minimum necessary if needed!)

		unsigned short flags;

		// Relay Certificates (ready after a CERTS cell is sent, nullptr if not present)

		unique_ptr<BriandTorCertificate_LinkKey> certLinkKey;
		unique_ptr<BriandTorCertificate_RSA1024Identity> certRsa1024Identity;
		unique_ptr<BriandTorCertificate_RSA1024AuthenticateCellLink> certRsa1024AuthenticateCell;
		unique_ptr<BriandTorCertificate_Ed25519SigningKey> certEd25519SigningKey;
		unique_ptr<BriandTorCertificate_TLSLink> certTLSLink;
		unique_ptr<BriandTorCertificate_Ed25519AuthenticateCellLink> certEd25519AuthenticateCellLink;
		unique_ptr<BriandTorCertificate_RSAEd25519CrossCertificate> certRSAEd25519CrossCertificate;

		// Descriptor's informations (ready after a FetchDescriptors() is called, empty if not present)

		/* OR Onion key, BASE64 ENCODED, LITTLE ENDIAN */
		unique_ptr<string> descriptorNtorOnionKey;
		
		// Temporary Curve25519 keys for the handshake

		/** A Curve25519 temporary public key, LITTLE ENDIAN */
		unique_ptr<vector<unsigned char>> CURVE25519_PUBLIC_KEY;
		/** A Curve25519 temporary private key, BIG ENDIAN */
		unique_ptr<vector<unsigned char>> CURVE25519_PRIVATE_KEY;
		

		// KEY EXCHANGE FIELDS
		
		/** SERVER's PK received within CREATED2 or EXTENDED2 cell WARNING: will be used and then released so never use without check if nullptr! LITTLE ENDIAN */
		unique_ptr<vector<unsigned char>> CREATED_EXTENDED_RESPONSE_SERVER_PK;
		/** SERVER's AUTH received within CREATED2 or EXTENDED2 cell WARNING: will be used and then released so never use without check if nullptr! */
		unique_ptr<vector<unsigned char>> CREATED_EXTENDED_RESPONSE_SERVER_AUTH;
		/** KEYSEED calculated after receiving CREATED2 or EXTENDED2 cell WARNING: will be used and then released so never use without check if nullptr! */
		unique_ptr<vector<unsigned char>> KEYSEED;

		/** ENCRYPTION AND DECRYPTION STUFF (available after the handshake is completed) */

		/** This is the Df (forward digest) extracted from the HKDF-SHA256 handshaked data in Create2 or Extend2. WARNING: nullptr until handshake completed. */
		unique_ptr<mbedtls_md_context_t> KEY_ForwardDigest_Df;
		/** This is the Db (backward digest) extracted from the HKDF-SHA256 handshaked data in Create2 or Extend2. WARNING: nullptr until handshake completed. */
		unique_ptr<mbedtls_md_context_t> KEY_BackwardDigest_Db;
		/** This is the Kf (forward AES key, for encryption) extracted from the HKDF-SHA256 handshaked data in Create2 or Extend2. WARNING: nullptr until handshake completed. */
		unique_ptr<vector<unsigned char>> KEY_Forward_Kf;
		/** This is the Kb (backward AES key, for decryption) extracted from the HKDF-SHA256 handshaked data in Create2 or Extend2. WARNING: nullptr until handshake completed. */
		unique_ptr<vector<unsigned char>> KEY_Backward_Kb;
		/** This is a nonce used in HiddenServices in place of  extracted from the HKDF-SHA256 handshaked data in Create2 or Extend2. WARNING: nullptr until handshake completed. */
		unique_ptr<vector<unsigned char>> KEY_HiddenService_Nonce;


		unique_ptr<esp_aes_context> AES_Forward_Context;
		unsigned int AES_Forward_NonceOffset;
		unique_ptr<vector<unsigned char>> AES_Forward_IV;
		unique_ptr<vector<unsigned char>> AES_Forward_Nonce;
		
		unique_ptr<esp_aes_context> AES_Backward_Context;
		unsigned int AES_Backward_NonceOffset;
		unique_ptr<vector<unsigned char>> AES_Backward_IV;
		unique_ptr<vector<unsigned char>> AES_Backward_Nonce;


		// ------------------------------

		BriandTorRelay();

		~BriandTorRelay();

		/**
		 * Method returns relay host
		 * @return host in string format 
		*/
		string GetHost();
		
		/**
		 * Method returns relay port
		 * @return port
		*/
		unsigned short GetPort();

		/**
		 * Method returns number of certificate loaded in this relay
		*/
		unsigned short GetCertificateCount();
		
		/**
		 * Method validates certificates as required in Tor handshake protocol.
		 * @return true if all valid, false if not.
		*/
		bool ValidateCertificates();
		
		/**
		 * Method fetches the relay (OR) descriptors needed by requesting it to an authority directory. 
		 * After calling this method descriptors will be populated.
		 * @return true if success, false instead
		*/
		bool FetchDescriptorsFromAuthority();

		/**
		 * Method (only if debug active) print all short info of certificates, order of CertType
		*/
		void PrintAllCertificateShortInfo();
		
		/**
		 * Method concludes the handshake starting from a CREATED2 or EXTENDED2 cell payload. 
		 * WARNING: All resources fields associated will be used and then released.
		 * @param created2_extended2_payload The pointer to payload of the received cell. 
		 * @return true if success, false instead.
		*/
		bool FinishHandshake(const unique_ptr<vector<unsigned char>>& created2_extended2_payload);

		/**
		 * Method (only if debug active) print short info about relay
		*/
		void PrintRelayInfo();
	};

}