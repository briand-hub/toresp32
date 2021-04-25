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
	class BriandTorCertificateUtils {
		public:

		/**
		 * Method perform SHA256 digest on the input bytes.
		 * @param input input bytes
		 * @return Pointer to vector containing hash.
		*/
		static unique_ptr<vector<unsigned char>> GetDigest_SHA256(const unique_ptr<vector<unsigned char>>& input);

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
		 * Method generates keypair and saves informations (keys and client to server vector) on given relay
		 * @param relay The destination relay for handshake
		 * @return true if success, false instead
		*/
		static bool ECDH_CURVE25519_GenKeys(BriandTorRelay& relay);

	};
}