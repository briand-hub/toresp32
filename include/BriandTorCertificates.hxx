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
#include "BriandTorDefinitions.hxx"

using namespace std;

namespace Briand {

	/**
	 * Base class just to define common methods and fields to simplify code. Valid for some certificates.
	*/
	class BriandTorCertificateBase : public BriandESPHeapOptimize {
		protected:

		public:

		static const char* LOGTAG;

		/** Cert Type */
		unsigned char Type;
		/** Maximum allowed certType */
		static const unsigned char MAX_CERT_VALUE = 7;
		/** Content bytes of the certificate (raw, not including header) */
		unique_ptr<vector<unsigned char>> Contents;

		/** Constructor inits the Contents vector */
		BriandTorCertificateBase();
	
		/** Copy constructor to avoid error "use of deleted function..." */
		BriandTorCertificateBase(const BriandTorCertificateBase& other);
		
		/** Destructor  */
		~BriandTorCertificateBase();

		/** 
		 * Method return certificate name human-readable (for debug). MUST be implemented by derived classes. 
		 * @return Certificate name (string)
		*/
		virtual string GetCertificateName() = 0;

		/**
		 * Method return string containing certificate type and raw bytes 
		 * @return string with short info
		*/
		string GetCertificateShortInfo();

		/**
		 * Print to serial certificate informations (debug) 
		*/
		virtual void PrintCertInfo();

		/** Inherited from BriandESPHeapOptimize */
		virtual void PrintObjectSizeInfo();
		/** Inherited from BriandESPHeapOptimize */
		virtual size_t GetObjectSize();

	};

	/**
	 * This is a support class, just keeps information about an Ed25519 certificate extension. 
	*/
	class BriandTorEd25519CertificateExtension : public BriandESPHeapOptimize {
		public:

		static const char* LOGTAG;

		unsigned short ExtLength; 	// [2 bytes]
        unsigned char ExtType;   	// [1 byte]
        unsigned char ExtFlags;		// [1 byte]
        unique_ptr<vector<unsigned char>> ExtData; // [ExtLength bytes]
		bool valid;	// built correctly

		/**
		 * Build extension starting from raw bytes. Please check valid attribute! 
		*/
		BriandTorEd25519CertificateExtension(const unique_ptr<vector<unsigned char>>& rawdata);

		/**
		 * Copy-constructor to avoid error: use of deleted function with make_unique
		*/
		BriandTorEd25519CertificateExtension(const BriandTorEd25519CertificateExtension& other);

		~BriandTorEd25519CertificateExtension();

		/**
		 * Method returns extension total size in bytes
		 * @return Extension size in bytes (header + data)
		*/
		unsigned int TotalSize();

		/** Inherited from BriandESPHeapOptimize */
		virtual void PrintObjectSizeInfo();
		/** Inherited from BriandESPHeapOptimize */
		virtual size_t GetObjectSize();
	};

	/**
	 * Base class just to define common methods and fields to simplify code. Valid for Ed25519 Tor certificates.
	 * See https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
	*/
	class BriandTorEd25519CertificateBase : public BriandESPHeapOptimize {
		protected:
		const unsigned short certified_key_len = 32;
		const unsigned short signature_len = 64;
		bool isStructValid;
		/* This will hold all non-signature parts to verify signature */
		unique_ptr<vector<unsigned char>> non_signature_parts;

		public:

		static const char* LOGTAG;

		/** Cert Type */
		unsigned char Type;
		unsigned char VERSION; // [1 Byte]
        unsigned char CERT_TYPE; // [1 Byte]
        unsigned int EXPIRATION_DATE; // [4 Bytes] HOURS since Unix epoch
        unsigned char CERT_KEY_TYPE;   // [1 byte]
        unique_ptr<vector<unsigned char>> CERTIFIED_KEY; // [32 Bytes] see certified_key_len
        unsigned char N_EXTENSIONS;    // [1 byte]
        unique_ptr<vector<BriandTorEd25519CertificateExtension>> EXTENSIONS; // [N_EXTENSIONS times]
        unique_ptr<vector<unsigned char>> SIGNATURE;       // [64 Bytes] see signature_len

		/**
		 * Constructor builds the certificate starting from the raw bytes. MUST call isStructValid() after
		 * @param raw_bytes Raw bytes (will not be touched or modified!) 
		*/
		BriandTorEd25519CertificateBase(const unique_ptr<vector<unsigned char>>& raw_bytes);

		~BriandTorEd25519CertificateBase();

		/**
		 * Method to check if certificate has been correctly built from raw bytes 
		 * @return true if valid, false otherwise
		*/
		virtual bool IsStructureValid();
	
		/**
		 * Method determines if certificate is expired (passed EXPIRATION_DATE (in hours!) since Unix epoch 
		 * @return true if expired , false if not
		*/
		virtual bool IsExpired();

		/**
		 * Method verify signature is validated by another Ed25519 public key
		 * @param ed25519PK Ed25519 public key 
		 * @return true if valid, false otherwise
		*/
		virtual bool IsSignatureIsValid(const unique_ptr<vector<unsigned char>>& ed25519PK);

		/** 
		 * Method return certificate name human-readable (for debug). MUST be implemented by derived classes. 
		 * @return Certificate name (string)
		*/
		virtual string GetCertificateName() = 0;

		/**
		 * Print to serial certificate informations (debug) 
		*/
		virtual void PrintCertInfo();

		/** Inherited from BriandESPHeapOptimize */
		virtual void PrintObjectSizeInfo();
		/** Inherited from BriandESPHeapOptimize */
		virtual size_t GetObjectSize();
	
	};

	/** CertType 2: RSA1024 Identity certificate, self-signed. DER encoded X509 */
	class BriandTorCertificate_RSA1024Identity : public BriandTorCertificateBase {
		public: 

		virtual string GetCertificateName();
		
		/**
		 * Method verify X.509 certificate (valid dates, signatures and chain) against itself
		 * @param signAuthenticator CA root certificate
		 * @return true if all valid, false otherwise 
		*/
		virtual bool IsValid();

		/**
		 * Method returns the RSA key length (in bits) of this certificate
		 * @return RSA key length in bits, 0 if error.
		*/
		virtual unsigned short GetRsaKeyLength();
		
	};

	/** CertType 7: Ed25519 identity, signed with RSA identity. Tor-specific format. 
	 * This class is useful to handle Tor specific RSA->Ed25519 Cross Certificate. 
	 * See https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
	*/
	class BriandTorCertificate_RSAEd25519CrossCertificate : public BriandESPHeapOptimize {
		private:
		const unsigned int ed25519_key_size = 32;
		bool isStructValid;

		protected:

		public:

		static const char* LOGTAG;

		/** Cert Type */
		unsigned char Type;
		unique_ptr<vector<unsigned char>> ED25519_KEY; // [32 bytes]
       	unsigned int EXPIRATION_DATE; // [4 bytes] HOURS since Unix epoch
       	unsigned char SIGLEN; // [1 byte]
        unique_ptr<vector<unsigned char>> SIGNATURE; // [SIGLEN bytes]

		/**
		 * Constructor builds the certificate starting from the raw bytes. MUST call isStructValid() after
		 * @param raw_bytes Raw bytes (will not be touched or modified!) 
		*/
		BriandTorCertificate_RSAEd25519CrossCertificate(const unique_ptr<vector<unsigned char>>& raw_bytes);

		~BriandTorCertificate_RSAEd25519CrossCertificate();

		/**
		 * Method to check if certificate has been correctly built from raw bytes 
		 * @return true if valid, false otherwise
		*/
		bool IsStructureValid();

		/**
		 * Method determines if certificate is expired (passed EXPIRATION_DATE (in hours!) since Unix epoch 
		 * @return true if expired , false if not
		*/
		bool IsExpired();

		/**
		 * Method validates the certificate (check signature validated by RSA 1024 Identity key) 
		*/
		bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator);

		/**
		 * Print to serial certificate informations (debug) 
		*/
		void PrintCertInfo();

		/** Inherited from BriandESPHeapOptimize */
		virtual void PrintObjectSizeInfo();
		/** Inherited from BriandESPHeapOptimize */
		virtual size_t GetObjectSize();

	};

	/** CertType 1: Link key certificate certified by RSA1024 identity. DER encoded X509 */
	class BriandTorCertificate_LinkKey : public BriandTorCertificateBase {
		public:
		
		virtual string GetCertificateName();

		/**
		 * Method verify X.509 certificate (valid dates, signatures and chain) against the CA provided
		 * @param signAuthenticator CA root certificate
		 * @return true if all valid, false otherwise 
		*/
		virtual bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator);
	};

	/** CertType 3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key. DER encoded X509 */
	class BriandTorCertificate_RSA1024AuthenticateCellLink : public BriandTorCertificateBase {
		public: 

		virtual string GetCertificateName();
		
		/**
		 * Method verify X.509 certificate (valid dates, signatures and chain) against the CA provided
		 * @param signAuthenticator CA root certificate
		 * @return true if all valid, false otherwise 
		*/
		virtual bool IsValid(const BriandTorCertificate_RSA1024Identity& signAuthenticator);

	};

	/** CertType 4: Ed25519 signing key, signed with RSA1024 Identity key. Tor-specific format. */
	class BriandTorCertificate_Ed25519SigningKey : public BriandTorEd25519CertificateBase {
		public:

		BriandTorCertificate_Ed25519SigningKey(const unique_ptr<vector<unsigned char>>& raw_bytes) : BriandTorEd25519CertificateBase(raw_bytes) {}

		virtual string GetCertificateName();

		virtual bool IsValid(const BriandTorCertificate_RSAEd25519CrossCertificate& signAuthenticator);

	};

	/** CertType 5: TLS link certificate, signed with ed25519 signing key. Tor-specific format. */
	class BriandTorCertificate_TLSLink : public BriandTorEd25519CertificateBase {
		public:

		BriandTorCertificate_TLSLink(const unique_ptr<vector<unsigned char>>& raw_bytes) : BriandTorEd25519CertificateBase(raw_bytes) {}

		virtual string GetCertificateName();

		virtual bool IsValid(const BriandTorCertificate_Ed25519SigningKey& signAuthenticator, const BriandTorCertificate_LinkKey& linkKeyCert);

	};

	/** CertType 6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key. Tor-specific format. */
	class BriandTorCertificate_Ed25519AuthenticateCellLink : public BriandTorEd25519CertificateBase {
		public:

		BriandTorCertificate_Ed25519AuthenticateCellLink(const unique_ptr<vector<unsigned char>>& raw_bytes) : BriandTorEd25519CertificateBase(raw_bytes) {}

		virtual string GetCertificateName();

		virtual bool IsValid(const BriandTorCertificate_Ed25519SigningKey& signAuthenticator);

	};

}