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

#include <iostream>
#include <memory>

#include "BriandTorRelay.hxx"

using namespace std;

namespace Briand {

	/* This class contains utility methods to perform hashing and certificate validation, depending on the chosen implementation/library */
	class BriandTorCryptoUtils {
		public:

		/**
		 * Method perform SHA256 digest on the input bytes.
		 * @param input input bytes
		 * @return Pointer to vector containing hash.
		*/
		static unique_ptr<vector<unsigned char>> GetDigest_SHA256(const unique_ptr<vector<unsigned char>>& input);

		/**
		 * Method perform SHA1 digest on the input bytes.
		 * @param input input bytes
		 * @return Pointer to vector containing hash.
		*/
		static unique_ptr<vector<unsigned char>> GetDigest_SHA1(const unique_ptr<vector<unsigned char>>& input);

		/**
		 * Method perform the digest (SHA1) of the running bytes sent/received with relay/relay_early cells (for handling tor node digest Df/Db)
		 * @param relayCurrentDigest The relay's digest context whom the cell is received/sent. Will be updated!
		 * @param relayCellPayload The relay cell payload (full, with digest field set to all zeros when sending cell, unencrypted when receiving cell)
		 * @return Pointer to vector containing hash.
		*/
		static unique_ptr<vector<unsigned char>> GetRelayCellDigest(unique_ptr<mbedtls_md_context_t>& relayCurrentDigest, const unique_ptr<vector<unsigned char>>& relayCellPayload);

		/**
		 * Method perform HMAC-SHA256 on the input bytes.
		 * @param input input bytes
		 * @param key key required for HMAC
		 * @return Pointer to vector containing result.
		*/
		static unique_ptr<vector<unsigned char>> GetDigest_HMAC_SHA256(const unique_ptr<vector<unsigned char>>& input, const unique_ptr<vector<unsigned char>>& key);

		/**
		 * Method calculates the HKDF-SHA256 (RFC5869) from given input.
		 * @param mExpand the info
		 * @param keySeed the salt
		 * @param bytesToProduce size needed
		 * @return Pointer to bytes (of size bytesToProduce)
		*/
		static unique_ptr<vector<unsigned char>> Get_HKDF(const unique_ptr<vector<unsigned char>>& mExpand, const unique_ptr<vector<unsigned char>>& keySeed, const unsigned int bytesToProduce);

		/**
		 * Method verifies SHA256 RSA PKCS#1 v1.5 signature
		 * @param message The message (raw data)
		 * @param x509DerCertificate The DER-encoded X.509 certificate containing the PublicKey (PK) to check signature
		 * @param signature Signature bytes
		 * @return true if valid, false instead 
		*/
		static bool CheckSignature_RSASHA256(const unique_ptr<vector<unsigned char>>& message, const unique_ptr<vector<unsigned char>>& x509DerCertificate, const unique_ptr<vector<unsigned char>>& signature);
		
		/**
		 * Method verifies a X.509 certificate against the provided root certificate
		 * @param x509PeerCertificate The  .509 peer certificate (DER endoded raw bytes or PEM-Encoded but with added null-termination)
		 * @param x509CACertificate The X.509 CA certificate (DER endoded raw bytes or PEM-Encoded but with added null-termination)
		 * @return true if valid, false instead 
		*/
		static bool X509Validate(const unique_ptr<vector<unsigned char>>& x509PeerCertificate, const unique_ptr<vector<unsigned char>>& x509CACertificate);

		/**
		 * Method verifies Ed25519 signature
		 * @param message The message (raw data)
		 * @param ed25519PK The Ed25519 public key
		 * @param signature Signature bytes
		 * @return true if valid, false instead 
		*/
		static bool CheckSignature_Ed25519(const unique_ptr<vector<unsigned char>>& message, const unique_ptr<vector<unsigned char>>& ed25519PK, const unique_ptr<vector<unsigned char>>& signature);

		/**
		 * Decode a base64 string to a vector<unsigned char>
		 * @param input The input string
		 * @return Pointer to vector<unsigned char> decoded content (empty if failed)
		*/
		static unique_ptr<vector<unsigned char>> Base64Decode(const string& input);

		/**
		 * Method generates public/private ECDH keypair from Curve25519 as Tor specifications, saves to relay. Uses G=9
		 * @param relay The relay where to save generated keys
		 * @return true on success, false otherwise.
		*/
		static bool ECDH_Curve25519_GenKeys(BriandTorRelay& relay);

		/**
		 * Method calculates the shared secret, given the private key and the server's public key. In Tor's equals to EXP(Y,x)
		 * @param serverPublic The server public key response (Y)
		 * @param privateKey The private key generated (x)
		 * @return Pointer to the shared secret (empty if fails!)
		*/
		static unique_ptr<vector<unsigned char>> ECDH_Curve25519_ComputeSharedSecret(const unique_ptr<vector<unsigned char>>& serverPublic, const unique_ptr<vector<unsigned char>>& privateKey);

		/**
		 * Method generates keypair and saves informations (keys and client to server vector) on given relay
		 * @param relay The relay to conclude handshake with. WARNING: MUST have initialized the ECDH_CURVE25519_CONTEXT, ECDH_CURVE25519_CLIENT_TO_SERVER, 
		 * CREATED_EXTENDED_RESPONSE_SERVER_PK and CREATED_EXTENDED_RESPONSE_SERVER_AUTH fields. Fields are NOT cleared after the work.
		 * @return true if success, false instead. If everything is ok, fields KEY_***** are populated.
		*/
		static bool NtorHandshakeComplete(BriandTorRelay& relay);

		/**
		 * Method encrypt AES 128 CTR mode (all-zero IV/nonce)
		 * @param content The content
		 * @param key The key
		 * @return Pointer to encrypted content
		*/
		static unique_ptr<vector<unsigned char>> AES128CTR_Encrypt(const unique_ptr<vector<unsigned char>>& content, const unique_ptr<vector<unsigned char>>& key);

		/**
		 * Method decrypt AES 128 CTR mode (all-zero IV/nonce)
		 * @param content The content
		 * @param key The key
		 * @return Pointer to decrypted content
		*/
		static unique_ptr<vector<unsigned char>> AES128CTR_Decrypt(const unique_ptr<vector<unsigned char>>& content, const unique_ptr<vector<unsigned char>>& key);



		/** WRONG METHOD
		 * Method generates keypair and saves informations (keys and client to server vector) on given relay
		 * @param relay The destination relay for handshake
		 * @return true if success, false instead
		*/
		/* WRONG METHOD static bool ECDH_CURVE25519_GenKeys(BriandTorRelay& relay); */

		/** WRONG METHOD
		 * Method computes the shared secret after an ECDH operation 
		 * @param serverToClient The ECDH server's response
		 * @param relay The relay that answered for handshake
		 * @return Pointer to the shared secret vector (bytes), empty if fails.
		*/
		/* WRONG METHOD  static unique_ptr<vector<unsigned char>> ECDH_CURVE25519_ComputeShared(const unique_ptr<vector<unsigned char>>& serverToClient, const BriandTorRelay& relay); */

	};
}