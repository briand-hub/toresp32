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
		unique_ptr<string> first_address;
		unique_ptr<string> fingerprint;
		unique_ptr<string> dir_address;
		unique_ptr<string> effective_family;
		
		// TODO : add exit policy summary accept/reject

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

		/* OR Onion key, BASE64 ENCODED */
		unique_ptr<string> descriptorNtorOnionKey;

		// TODO: handle more fields (minimum necessary if needed!)
		
		// This part is library-dependent :/ at moment using mbedtls
		unique_ptr<mbedtls_ecdh_context> ECDH_CURVE25519_CONTEXT;
		// The bytes to send to the server to perform DH handshake
		unique_ptr<vector<unsigned char>> ECDH_CURVE25519_CLIENT_TO_SERVER;

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
		 * Method fetches the relay (OR) descriptors needed by requesting <dir_address>/tor/server/authority
		 *  WARNING: request to the relay and not to authority at moment due to high space requirements for downloading consensus!!
		 * @param secureRequest Use http (false) or https (true)
		 * @return true if success, false instead
		*/
		bool FetchDescriptorsFromOR(bool secureRequest = false);
		
		/**
		 * Method (only if debug active) print all short info of certificates, order of CertType
		*/
		void PrintAllCertificateShortInfo();
		
		/**
		 * Method (only if debug active) print short info about relay
		*/
		void PrintRelayInfo();
	};

}