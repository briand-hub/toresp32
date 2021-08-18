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

#include "BriandTorCell.hxx"
#include "BriandTorCryptoUtils.hxx"
#include "BriandNet.hxx"

using namespace std;

namespace Briand {

	void BriandTorCell::PadPayload() {
		/* 
			April 2021

			The cell is padded up to the cell length with padding bytes.

			Senders set padding bytes depending on the cell's command:

				VERSIONS:  Payload MUST NOT contain padding bytes.
				AUTHORIZE: Payload is unspecified and reserved for future use.
				Other variable-length cells:
							Payload MAY contain padding bytes at the end of the cell.
							Padding bytes SHOULD be set to NUL.
				RELAY/RELAY_EARLY: Payload MUST be padded to PAYLOAD_LEN with padding
							bytes. Padding bytes SHOULD be set to random values.
				Other fixed-length cells:
							Payload MUST be padded to PAYLOAD_LEN with padding bytes.
							Padding bytes SHOULD be set to NUL.

			We recommend random padding in RELAY/RELAY_EARLY cells, so that the cell
			content is unpredictable. See the format of relay cells in section 6.1
			for detail.

			For other cells, TLS authenticates cell content, so randomized padding
			bytes are redundant.

			Receivers MUST ignore padding bytes.

			PADDING cells are currently used to implement connection keepalive.
			If there is no other traffic, ORs and OPs send one another a PADDING
			cell every few minutes.
		*/

		if (this->Command == Briand::BriandTorCellCommand::VERSIONS || this->Command == Briand::BriandTorCellCommand::AUTHORIZE) {
			// no pad
			return;
		}
		else if (this->Command == Briand::BriandTorCellCommand::RELAY || this->Command == Briand::BriandTorCellCommand::RELAY_EARLY) {
			// random pad
			//while (this->Payload->size() < this->PAYLOAD_LEN)
			//	this->Payload->push_back( Briand::BriandUtils::GetRandomByte() );

			// Modified ! the padding for relay cells is done in the PrepareAsRelayCell method
		}
		else {
			// May...?
			while (this->Payload->size() < this->PAYLOAD_LEN)
				this->Payload->push_back( 0x00 );
		}
	}

	BriandTorCell::BriandTorCell(const unsigned char& link_protocol_version, const unsigned int& circid, const Briand::BriandTorCellCommand& command) {
		this->linkProtocolVersion = link_protocol_version;

		this->CircID = circid;
		this->Command = command;

		if (this->Command == Briand::BriandTorCellCommand::VERSIONS || static_cast<unsigned int>(this->Command) >= 128) 
			this->isVariableLengthCell = true;
		else
			this->isVariableLengthCell = false;
		
		// Init the payload bytes, depending if this is a fixed cell or not the size may vary.
		// Additionally to save more RAM, padding will be done directly.

		this->Payload = make_unique<vector<unsigned char>>();
		this->Payload->reserve(PAYLOAD_LEN);

		this->cellTotalSizeBytes = 0;

		this->FullDigest = nullptr;
		this->StreamID = USHRT_MAX;
	}

	BriandTorCell::~BriandTorCell() {
		this->Payload->clear();
		this->Payload->resize(1);
		this->Payload.reset();
		if (this->FullDigest != nullptr) this->FullDigest.reset();
	}

	bool BriandTorCell::AppendToPayload(const unsigned char& byte) {
		if (this->Payload->size() + 1 > this->PAYLOAD_LEN)
			return false;

		this->Payload->push_back(byte);
		return true;
	}

	bool BriandTorCell::AppendTwoBytesToPayload(const unsigned short& what) {
		if (this->Payload->size() + 2 > this->PAYLOAD_LEN)
			return false;

		this->Payload->push_back( static_cast<unsigned char>( (what & 0xFF00) >> 8 ) );
		this->Payload->push_back( static_cast<unsigned char>( (what & 0x00FF) ) );

		return true;
	}

	bool BriandTorCell::AppendFourBytesToPayload(const unsigned int& what) {
		if (this->Payload->size() + 4 > this->PAYLOAD_LEN)
			return false;

		this->AppendToPayload( static_cast<unsigned char>( (what & 0xFF000000) >> 24 ) );
		this->AppendToPayload( static_cast<unsigned char>( (what & 0x00FF0000) >> 16 ) );
		this->AppendToPayload( static_cast<unsigned char>( (what & 0x0000FF00) >> 8 ) );
		this->AppendToPayload( static_cast<unsigned char>( (what & 0x000000FF) ) );

		return true;
	}

	bool BriandTorCell::AppendBytesToPayload(vector<unsigned char>& what) {
		if (this->Payload->size() + what.size() > this->PAYLOAD_LEN)
			return false;

		this->Payload->insert(this->Payload->begin() + this->Payload->size(), what.begin(), what.end());

		return true;
	}

	void BriandTorCell::ClearPayload() {
		this->Payload->clear();
	}

	void BriandTorCell::PrintCellPayloadToSerial() {
		Briand::BriandUtils::PrintByteBuffer( *(this->Payload.get()) , this->Payload->size(), this->Payload->size() );
	}

	unique_ptr<vector<unsigned char>> BriandTorCell::SendCell(unique_ptr<BriandIDFSocketTlsClient>& client, bool closeConnection /* = false*/, bool expectResponse /* = true */) {
		// Prepare the cell header and pad payload if necessary
		auto cellBuffer = make_unique<vector<unsigned char>>();
		cellBuffer->reserve(MAX_CELL_SIZE);

		/*
			Apr 2021
			On a version 1 connection, each cell contains the following
			fields:

					CircID                                [CIRCID_LEN bytes]
					Command                               [1 byte]
					Payload (padded with padding bytes)   [PAYLOAD_LEN bytes]

			On a version 2 or higher connection, all cells are as in version 1
			connections, except for variable-length cells, whose format is:

					CircID                                [CIRCID_LEN octets]
					Command                               [1 octet]
					Length                                [2 octets; big-endian integer]
					Payload (some commands MAY pad)       [Length bytes]
		*/

		// CircID may vary

		if (this->Command == Briand::BriandTorCellCommand::VERSIONS || this->linkProtocolVersion < 4) {
			// CircID is 2 bytes
			cellBuffer->push_back( static_cast<unsigned char>( (this->CircID & 0xFF00 ) >> 8 ));
			cellBuffer->push_back( static_cast<unsigned char>( (this->CircID & 0x00FF ) ));
		}
		else if (this->linkProtocolVersion >= 4) {
			// CircID is 4 bytes
			cellBuffer->push_back( static_cast<unsigned char>( (this->CircID & 0xFF000000 ) >> 24 ));
			cellBuffer->push_back( static_cast<unsigned char>( (this->CircID & 0x00FF0000 ) >> 16));
			cellBuffer->push_back( static_cast<unsigned char>( (this->CircID & 0x0000FF00 ) >> 8 ));
			cellBuffer->push_back( static_cast<unsigned char>( (this->CircID & 0x000000FF ) ));
		}

		// 1 byte for Command, always
		cellBuffer->push_back( static_cast<unsigned char>(this->Command) );

		// If variable-length cell, 2 bytes must be added, containing payload len
		if (this->isVariableLengthCell) {
			cellBuffer->push_back( static_cast<unsigned char>( (this->Payload->size() & 0xFF00 ) >> 8 ));
			cellBuffer->push_back( static_cast<unsigned char>( (this->Payload->size() & 0x00FF ) ));
		}

		// Pad payload (will check itself if it is needed)
		this->PadPayload();

		// Append payload to cellBuffer
		cellBuffer->insert(cellBuffer->end(), this->Payload->begin(), this->Payload->end());

		this->cellTotalSizeBytes = cellBuffer->size();

		ESP_LOGD(LOGTAG, "[DEBUG] %s Cell of %d bytes is going to be sent. Contents: ", Briand::BriandUtils::BriandTorCellCommandToString(this->Command).c_str(), cellBuffer->size());
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			Briand::BriandUtils::PrintByteBuffer( *(cellBuffer.get()), this->cellTotalSizeBytes, this->cellTotalSizeBytes );
		} 

		// That's all, send cell through network!
		auto response = BriandNet::RawSecureRequest(client, cellBuffer, true, closeConnection, expectResponse); // clear cell buffer after request to save ram.

		cellBuffer.reset(); // free ram

		return std::move(response);
	}

	bool BriandTorCell::BuildFromBuffer(unique_ptr<vector<unsigned char>>& buffer, const unsigned char& link_protocol_version) {
		cellTotalSizeBytes = 0;

		if (link_protocol_version > 0) {
			this->linkProtocolVersion = link_protocol_version;
		}
		
		// Clear all current informations
		this->CircID = 0;
		this->Command = Briand::BriandTorCellCommand::PADDING;
		this->isVariableLengthCell = false;
		this->ClearPayload();
		
		// check length
		if (buffer->size() < 5) {
			ESP_LOGD(LOGTAG, "[DEBUG] Insufficient length (less than 5 bytes).\n");
			return false;
		}

		unsigned short nextFrom = 0;

		// CircID
		if (this->linkProtocolVersion < 4) {
			// CircID is 2 bytes, VERSION cells are always 2 bytes
			ESP_LOGD(LOGTAG, "[DEBUG] Link protocol <4 (Ver.%u)\n", this->linkProtocolVersion);
			this->CircID += static_cast<unsigned int>(buffer->at(0) << 8);
			this->CircID += static_cast<unsigned int>(buffer->at(1));
			nextFrom = 2;
			cellTotalSizeBytes += 2;
		}
		else {
			// CircID is 4 bytes
			ESP_LOGD(LOGTAG, "[DEBUG] Link protocol >=4. (Ver. %u)\n", this->linkProtocolVersion);
			this->CircID += static_cast<unsigned int>(buffer->at(0) << 24);
			this->CircID += static_cast<unsigned int>(buffer->at(1) << 16);
			this->CircID += static_cast<unsigned int>(buffer->at(2) << 8);
			this->CircID += static_cast<unsigned int>(buffer->at(3));
			nextFrom = 4;
			cellTotalSizeBytes += 4;
		}

		// Command 1 byte
		this->Command = static_cast<Briand::BriandTorCellCommand>( buffer->at(nextFrom) );
		nextFrom += 1;
		cellTotalSizeBytes += 1;

		ESP_LOGD(LOGTAG, "[DEBUG] Cell command is %s\n", Briand::BriandUtils::BriandTorCellCommandToString(this->Command).c_str() );

		// Command => I know if is variable length cell
		if (this->Command == Briand::BriandTorCellCommand::VERSIONS || static_cast<unsigned int>(this->Command) >= 128) 
			this->isVariableLengthCell = true;

		// If variable length cell then I must have 2 bytes for Length and [Length] bytes more
		if(this->isVariableLengthCell && (buffer->size() - nextFrom) < 2) {
			ESP_LOGD(LOGTAG, "[DEBUG] Variable-length cell has insufficient length.\n");
			return false;
		}
		
		if (this->isVariableLengthCell) {
			// Get the size of payload (may be more, but should be ignored)
			unsigned short length = 0;
			length += static_cast<unsigned short>(buffer->at(nextFrom) << 8);
			length += static_cast<unsigned short>(buffer->at(nextFrom+1));
			nextFrom += 2;
			cellTotalSizeBytes += 2;

			if ((buffer->size() - nextFrom) < length) {
				ESP_LOGD(LOGTAG, "[DEBUG] Variable-length cell has insufficient payload length.\n");
				return false;
			}

			// Read all payload
			this->Payload->insert(this->Payload->begin(), buffer->begin() + nextFrom, buffer->begin() + nextFrom + length);

			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Variable-length cell payload: ");
				Briand::BriandUtils::PrintByteBuffer( *(this->Payload.get()), 128 );
			} 
		}
		else {
			// All the rest, for a maximum of PAYLOAD_LEN, is payload

			// Check if buffer is invalid in size.
			if (buffer->size() < nextFrom+PAYLOAD_LEN) {
				ESP_LOGW(LOGTAG, "[WARN] An invalid size cell of %zu bytes received instead of expected %d bytes. Saving only the available payload.\n", buffer->size(), nextFrom+PAYLOAD_LEN);
				// Save just the available payload
				this->Payload->insert(this->Payload->begin(), buffer->begin() + nextFrom, buffer->end());
			}
			else {
				// Save the full payload
				this->Payload->insert(this->Payload->begin(), buffer->begin() + nextFrom, buffer->begin() + nextFrom + PAYLOAD_LEN);
				ESP_LOGD(LOGTAG, "[DEBUG] Fixed cell payload of %d bytes.\n", this->Payload->size());
			}
		}

		cellTotalSizeBytes += this->Payload->size();

		return true;
	}

	BriandTorCellCommand BriandTorCell::GetCommand() {
		return this->Command;
	}

	unique_ptr<vector<unsigned char>>& BriandTorCell::GetPayload() {
		return this->Payload;
	}

	unsigned int BriandTorCell::GetCircID() {
		return this->CircID;
	}

	bool BriandTorCell::IsVariableLengthCell() {
		return this->isVariableLengthCell;
	}

	unsigned long int BriandTorCell::GetCellTotalSizeBytes() {
		return this->cellTotalSizeBytes;
	}

	unsigned short BriandTorCell::GetLinkProtocolFromVersionCell() {
		if (this->Command != Briand::BriandTorCellCommand::VERSIONS || this->Payload->size() < 2 || this->Payload->size() % 2 != 0) 
			return 0;
		
		// Payload should contain couples of bytes for each supported protocol version.
		unsigned short highest = 0;

		for (int i = 0; i<this->Payload->size(); i += 2) {
			unsigned short current = 0;
			current += static_cast<unsigned short>(this->Payload->at(i) << 8);
			current += static_cast<unsigned short>(this->Payload->at(i+1));
			if (current > highest)
				highest = current;
		}

		return highest;
	}

	bool BriandTorCell::SetRelayCertificatesFromCertsCell(unique_ptr<Briand::BriandTorRelay>& relay) {
		if (this->Command != Briand::BriandTorCellCommand::CERTS || this->Payload->size() < 3)
			return false;
		
		/*
			The CERTS cell describes the keys that a Tor instance is claiming
			to have.  It is a variable-length cell.  Its payload format is:

					N: Number of certs in cell            [1 octet]
					N times:
					CertType                           [1 octet]
					CLEN                               [2 octets]
					Certificate                        [CLEN octets]
		*/

		// First byte has number of certs
		unsigned char NCerts = this->Payload->at(0);
		unsigned long int startIndex = 1;
		for (unsigned char curCert = 0; curCert<NCerts; curCert++) {
			// First byte => cert type
			unsigned char certType = this->Payload->at(startIndex);
			startIndex++;

			// check if ok
			if ( certType <= 0 || certType > BriandTorCertificateBase::MAX_CERT_VALUE ) {
				ESP_LOGD(LOGTAG, "[DEBUG] Invalid CERTS cell content (%d is not a valid range certType).\n", certType);
				return false;
			}

			/*
				Relevant certType values are:
				1: Link key certificate certified by RSA1024 identity
				2: RSA1024 Identity certificate, self-signed.
				3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.
				4: Ed25519 signing key, signed with identity key.
				5: TLS link certificate, signed with ed25519 signing key.
				6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.
				7: Ed25519 identity, signed with RSA identity.
			*/

			ESP_LOGD(LOGTAG, "[DEBUG] Certificate %u (of %u) is certType %u.\n", curCert+1, NCerts, certType);

			// 2 bytes for length
			unsigned short certLen = 0;
			certLen += static_cast<unsigned short>(this->Payload->at(startIndex) << 8);
			certLen += static_cast<unsigned short>(this->Payload->at(startIndex+1));
			startIndex += 2;

			ESP_LOGD(LOGTAG, "[DEBUG] Certificate len is %u bytes.\n", certLen);

			// Payload should contain at least this length
			if (this->Payload->size() - startIndex < certLen) {
				ESP_LOGD(LOGTAG, "[DEBUG] Invalid CERTS cell content size.\n");
				return false;
			}

			auto edBuf = make_unique<vector<unsigned char>>(); // temp buffer in case of ed25519 certs (must be built on contructor)
			edBuf->reserve(MAX_CELL_SIZE); // reserve some bytes

			switch (certType) {
				case 0x01:
					relay->certLinkKey = make_unique<BriandTorCertificate_LinkKey>();
					relay->certLinkKey->Type = certType;
					// Read certificate content
					for (int i = startIndex; i < startIndex + certLen; i++ ) relay->certLinkKey->Contents->push_back( this->Payload->at(i) );
				break;
				case 0x02:
					relay->certRsa1024Identity = make_unique<BriandTorCertificate_RSA1024Identity>();
					relay->certRsa1024Identity->Type = certType;
					// Read certificate content
					for (int i = startIndex; i < startIndex + certLen; i++ ) relay->certRsa1024Identity->Contents->push_back( this->Payload->at(i) );
				break;
				case 0x03:
					relay->certRsa1024AuthenticateCell = make_unique<BriandTorCertificate_RSA1024AuthenticateCellLink>();
					relay->certRsa1024AuthenticateCell->Type = certType;
					// Read certificate content
					for (int i = startIndex; i < startIndex + certLen; i++ ) relay->certRsa1024AuthenticateCell->Contents->push_back( this->Payload->at(i) );
				break;
				case 0x04:
					// Build directly
					edBuf->insert(edBuf->begin(), this->Payload->begin() + startIndex, this->Payload->begin() + startIndex + certLen);
					relay->certEd25519SigningKey = make_unique<BriandTorCertificate_Ed25519SigningKey>(edBuf);
					relay->certEd25519SigningKey->Type = certType;
					// Check structure validity
					if (!relay->certEd25519SigningKey->IsStructureValid()) {
						// debug message handled by IsStructureValid()
						return false;
					}
				break;
				case 0x05:
					// Build directly
					edBuf->insert(edBuf->begin(), this->Payload->begin() + startIndex, this->Payload->begin() + startIndex + certLen);
					relay->certTLSLink = make_unique<BriandTorCertificate_TLSLink>(edBuf);
					relay->certTLSLink->Type = certType;
					// Check structure validity
					if (!relay->certTLSLink->IsStructureValid()) {
						// debug message handled by IsStructureValid()
						return false;
					}
				break;
				case 0x06:
					// Build directly
					edBuf->insert(edBuf->begin(), this->Payload->begin() + startIndex, this->Payload->begin() + startIndex + certLen);
					relay->certEd25519AuthenticateCellLink = make_unique<BriandTorCertificate_Ed25519AuthenticateCellLink>(edBuf);
					relay->certEd25519AuthenticateCellLink->Type = certType;
					// Check structure validity
					if (!relay->certEd25519AuthenticateCellLink->IsStructureValid()) {
						// debug message handled by IsStructureValid()
						return false;
					}
				break;
				case 0x07:
					edBuf->insert(edBuf->begin(), this->Payload->begin() + startIndex, this->Payload->begin() + startIndex + certLen);
					relay->certRSAEd25519CrossCertificate = make_unique<BriandTorCertificate_RSAEd25519CrossCertificate>(edBuf);
					relay->certRSAEd25519CrossCertificate->Type = certType;
					// Check structure validity
					if (!relay->certRSAEd25519CrossCertificate->IsStructureValid()) {
						// debug message handled by IsStructureValid()
						return false;
					}
				break;
				default:
				break;
			}

			edBuf.reset();

			startIndex += certLen;
		}

		return true;
	}

	void BriandTorCell::BuildAsNETINFO(const struct in_addr& yourPublicIP) {
		/*
			The cell's payload is:
			TIME       (Timestamp)                     [4 bytes]
			OTHERADDR  (Other OR's address)            [variable]
				ATYPE   (Address type)                  [1 byte]
				ALEN    (Adress length)                 [1 byte]
				AVAL    (Address value in NBO)          [ALEN bytes]
			NMYADDR    (Number of this OR's addresses) [1 byte]
				NMYADDR times:
				ATYPE   (Address type)                 [1 byte]
				ALEN    (Adress length)                [1 byte]
				AVAL    (Address value in NBO))        [ALEN bytes]
		*/
		
		// payload clearing if previously used
		this->ClearPayload();

		// reset command to netinfo
		this->Command = BriandTorCellCommand::NETINFO;

		/* The timestamp is a big-endian unsigned integer number of seconds since the Unix epoch */
		this->AppendFourBytesToPayload( static_cast<unsigned int>( BriandUtils::GetUnixTime() ) );

		// OTHERADDR ... just one!

		/* [04] IPv4. [06] IPv6. */
		// Actually Arduino seems to support just IPv4 so...
		unsigned char IPV = 4;
		unsigned char IPSIZE;
		this->AppendToPayload(IPV);

		/* ALEN MUST be 4 when ATYPE is 0x04 (IPv4) and 16 when ATYPE is 0x06 (IPv6). */
		if (IPV == 4) {
			IPSIZE = 4;
		} 
		else if (IPV == 6) {
			IPSIZE = 16;
		} 

		//
		// TODO : add IPV6 Support
		//

		this->AppendToPayload(IPSIZE);

		/* Append IP bytes, reverse order! */
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0x000000FF) >> 0 ));
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0x0000FF00) >> 8 ));
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0x00FF0000) >> 16 ));
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0xFF000000) >> 24 ));
		
		/* NMYADDR , same infos ... */
		// one address
		this->AppendToPayload(0x01);
		this->AppendToPayload(IPV);
		this->AppendToPayload(IPSIZE);
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0x000000FF) >> 0 ));
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0x0000FF00) >> 8 ));
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0x00FF0000) >> 16 ));
		this->AppendToPayload( static_cast<unsigned char>( (yourPublicIP.s_addr & 0xFF000000) >> 24 ));
	}

	bool BriandTorCell::BuildAsCREATE2(BriandTorRelay& relay) {
		// payload clearing if previously used
		this->ClearPayload();

		// reset command
		this->Command = BriandTorCellCommand::CREATE2;

		/*
			A CREATE2 cell contains:

			HTYPE     (Client Handshake Type)     [2 bytes]
			HLEN      (Client Handshake Data Len) [2 bytes]
			HDATA     (Client Handshake Data)     [HLEN bytes]
		*/

		// Set HTYPE to 0x0002  ntor -- the ntor+curve25519+sha256 handshake; see 5.1.4
		this->AppendTwoBytesToPayload(0x0002);

		/*
			This handshake uses a set of DH handshakes to compute a set of
			shared keys which the client knows are shared only with a particular
			server, and the server knows are shared with whomever sent the
			original handshake (or with nobody at all).  Here we use the
			"curve25519" group and representation as specified in "Curve25519:
			new Diffie-Hellman speed records" by D. J. Bernstein.

				In this section, define:

				H(x,t) as HMAC_SHA256 with message x and key t.
				H_LENGTH  = 32.
				ID_LENGTH = 20.
				G_LENGTH  = 32
				PROTOID   = "ntor-curve25519-sha256-1"
				t_mac     = PROTOID | ":mac"
				t_key     = PROTOID | ":key_extract"
				t_verify  = PROTOID | ":verify"
				MULT(a,b) = the multiplication of the curve25519 point 'a' by the
							scalar 'b'.
				G         = The preferred base point for curve25519 ([9])
				KEYGEN()  = The curve25519 key generation algorithm, returning
							a private/public keypair.
				m_expand  = PROTOID | ":key_expand"
				KEYID(A)  = A
		*/

		/*
			To perform the handshake, the client needs to know an identity key
			digest for the server, and an ntor onion key (a curve25519 public
			key) for that server. Call the ntor onion key "B".  The client
			generates a temporary keypair:
	
			x,X = KEYGEN()
		*/

		// Generate Curve25519 keys
		if (!BriandTorCryptoUtils::ECDH_Curve25519_GenKeys(relay)) {
			ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 construction failed because Curve25519 key generation failed.\n");
			return false;
		}

		// The identity digest is the node's fingerprint! 
		// (that is, verified by sending a CREATE2 with a correct one -> received CREATED2, with a wrong one received DESTROY! :D)
		// The onion key is retrieved by relay information from descriptor

		/*
			and generates a client-side handshake with contents:

			NODEID      Server identity digest  [ID_LENGTH bytes]
			KEYID       KEYID(B)                [H_LENGTH bytes]
			CLIENT_PK   X                       [G_LENGTH bytes]
		*/

		constexpr unsigned short ID_LENGTH = 20;
		constexpr unsigned short H_LENGTH = 32;
		constexpr unsigned short G_LENGTH = 32;

		// so....
		constexpr unsigned short HLEN = ID_LENGTH + H_LENGTH + G_LENGTH;

		this->AppendTwoBytesToPayload(HLEN);

		// Append fingerprint
		// Check
		auto fingerprintBytes = BriandUtils::HexStringToVector(*relay.fingerprint.get(), "");
		if (fingerprintBytes->size() != ID_LENGTH) {
			ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 construction failed because relay fingerprint was expected to have %u bytes but it has %u\n", ID_LENGTH, fingerprintBytes->size());
			return false;
		}
		this->AppendBytesToPayload(*fingerprintBytes.get());

		// Append ntor onion key, decoded
		auto KEYID = BriandTorCryptoUtils::Base64Decode(*relay.descriptorNtorOnionKey.get());
		// Check
		if (KEYID->size() != H_LENGTH) {
			ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 construction failed because relay ntor key was expected to have %u bytes but decoded has %u\n", H_LENGTH, KEYID->size());
			return false;
		}
		this->AppendBytesToPayload(*KEYID.get());

		// Append the CLIENT_PK
		// Check
		if (relay.CURVE25519_PUBLIC_KEY->size() != G_LENGTH) {
			ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 construction failed because Curve25519 size was expected to be %u bytes but has %u\n", G_LENGTH, relay.CURVE25519_PUBLIC_KEY->size());
			return false;
		}
		this->AppendBytesToPayload(*relay.CURVE25519_PUBLIC_KEY.get());

		ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 cell built with success.\n");

		return true;
	}

	bool BriandTorCell::BuildAsEXTEND2(BriandTorRelay& extendWithRelay) {
		// payload clearing if previously used
		this->ClearPayload();

		// The contents of EXTEND2 are the same as CREATE2, with more header data.
		if (!this->BuildAsCREATE2(extendWithRelay)) {
			ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 Relay cell failed construction because CREATE2 contents in failure!\n");
			return false;
		}

		/*
			An EXTEND2 cell's relay payload contains:

			NSPEC      (Number of link specifiers)     [1 byte]
				NSPEC times:
				LSTYPE (Link specifier type)           [1 byte]
				LSLEN  (Link specifier length)         [1 byte]
				LSPEC  (Link specifier)                [LSLEN bytes]

			==> the rest is the same as CREATE2

			HTYPE      (Client Handshake Type)         [2 bytes]
			HLEN       (Client Handshake Data Len)     [2 bytes]
			HDATA      (Client Handshake Data)         [HLEN bytes]
		*/

		// reset command
		
		/* 	
			When speaking v2 of the link protocol or later, clients MUST only send
   			EXTEND/EXTEND2 cells inside RELAY_EARLY cells
		*/

		this->Command = BriandTorCellCommand::RELAY_EARLY;

		// header to prepend
		auto extend2Header = make_unique<vector<unsigned char>>();
		extend2Header->reserve(256); // reserve some bytes

		// No. of link specifier 
		extend2Header->push_back(0x02);
		
		// [00] TLS-over-TCP, IPv4 address - A four-byte IPv4 address plus two-byte ORPort

		extend2Header->push_back(0x00); // LSTYPE
		extend2Header->push_back(0x06); // LSLEN 4 bytes ip + 2 bytes port
		
		struct in_addr relay_ip;
		inet_aton(extendWithRelay.address->c_str(), &relay_ip);

		// Append OR IPv4
		extend2Header->push_back( static_cast<unsigned char>( (relay_ip.s_addr & 0x000000FF) >> 0 ));
		extend2Header->push_back( static_cast<unsigned char>( (relay_ip.s_addr & 0x0000FF00) >> 8 ));
		extend2Header->push_back( static_cast<unsigned char>( (relay_ip.s_addr & 0x00FF0000) >> 16 ));
		extend2Header->push_back( static_cast<unsigned char>( (relay_ip.s_addr & 0xFF000000) >> 24 ));

		// Append OR Port
		extend2Header->push_back( static_cast<unsigned char>( (extendWithRelay.port & 0xFF00) >> 8 ) );
		extend2Header->push_back( static_cast<unsigned char>( (extendWithRelay.port & 0x00FF) >> 0 ) );

		// [02] Legacy identity - A 20-byte SHA1 identity fingerprint. At most one may be listed.
		
		extend2Header->push_back(0x02); // LSTYPE
		extend2Header->push_back(0x14); // LSLEN 20 bytes (=0x14 in hex :-P)
		auto fingerprintBytes = BriandUtils::HexStringToVector(*extendWithRelay.fingerprint.get(), "");
		extend2Header->insert(extend2Header->end(), fingerprintBytes->begin(), fingerprintBytes->end());
				
		//
		// TODO : add more identifiers if available
		// 

		// [03] Ed25519 identity - A 32-byte Ed25519 identity fingerprint. At most one may be listed.

		// [01] TLS-over-TCP, IPv6 address - A sixteen-byte IPv6 address plus two-byte ORPort


		// Prepend header bytes
		this->Payload->insert(this->Payload->begin(), extend2Header->begin(), extend2Header->end());

		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 cell built with success.\n");

		return true;
	}

	unsigned short BriandTorCell::GetStreamID() {
		return this->StreamID;
	}

	unsigned short BriandTorCell::GetRecognized() {
		return this->Recognized;
	}

	BriandTorCellRelayCommand BriandTorCell::GetRelayCommand() {
		return this->RelayCommand;
	}

	unique_ptr<vector<unsigned char>>& BriandTorCell::GetRelayCellDigest() {
		return this->FullDigest;
	}

	void BriandTorCell::PrepareAsRelayCell(const BriandTorCellRelayCommand& command, const unsigned short& streamID, unique_ptr<mbedtls_md_context_t>& digestForward) {
		
		// Assume payload ready

		/*
			Relay command           [1 byte]
			'Recognized'            [2 bytes]
			StreamID                [2 bytes]
			Digest                  [4 bytes]
			Length                  [2 bytes]
			Data                    [Length bytes]
			Padding                 [PAYLOAD_LEN - 11 - Length bytes]
		*/

		// Set default values
		this->StreamID = streamID;
		this->Recognized = 0x0000;
		this->RelayCommand = command;
		this->Digest = 0x00000000;
		
		auto relayCellHeader = make_unique<vector<unsigned char>>();
		relayCellHeader->reserve(32); // reserve some bytes

		// Relay command
		relayCellHeader->push_back(command);

		/*
			The 'recognized' field is used as a simple indication that the cell
			is still encrypted. It is an optimization to avoid calculating
			expensive digests for every cell. When sending cells, the unencrypted
			'recognized' MUST be set to zero
		*/

		relayCellHeader->push_back(0x00);
		relayCellHeader->push_back(0x00);

		/*
			All RELAY cells pertaining to the same tunneled stream have the same
   			stream ID.  StreamIDs are chosen arbitrarily by the OP.  No stream
   			may have a StreamID of zero.
		*/

		relayCellHeader->push_back(static_cast<unsigned char>( (this->StreamID & 0xFF00) >> 8 ));
		relayCellHeader->push_back(static_cast<unsigned char>( (this->StreamID & 0x00FF) >> 0 ));

		// Get the real length of the current encrypted payload because digest must be done
		// also on the padding bytes.
		unsigned short payloadLen = this->Payload->size();

		// Pad now the payload, adding random bytes till PAYLOAD_LEN minus the 11 header bytes
		/*
			Implementations SHOULD fill this field with four zero-valued bytes, followed by as many
			random bytes as will fit.  (If there are fewer than 4 bytes for padding,
			then they should all be filled with zero.
		*/

		while (this->Payload->size() < this->PAYLOAD_LEN - 11 && this->Payload->size() < payloadLen + 4)
			this->Payload->push_back(0x00);
		
		while (this->Payload->size() < this->PAYLOAD_LEN - 11)
			this->Payload->push_back( Briand::BriandUtils::GetRandomByte() );

		// Digest : no particular function specified, so assuming SHA1 but seeded version

		/*
			the 'digest' field is computed as
			the first four bytes of the running digest of all the bytes that have
			been destined for this hop of the circuit or originated from this hop
			of the circuit, seeded from Df or Db respectively (obtained in
			section 5.2 above), and including this RELAY cell's entire payload
			(taken with the digest field set to zero).  Note that these digests
			_do_ include the padding bytes at the end of the cell, not only those up
			to "Len".
		*/

		// First: set digest field to zero (4 bytes)

		relayCellHeader->push_back(0x00);
		relayCellHeader->push_back(0x00);
		relayCellHeader->push_back(0x00);
		relayCellHeader->push_back(0x00);

		// Length
		relayCellHeader->push_back(static_cast<unsigned char>( (payloadLen & 0xFF00) >> 8 ));
		relayCellHeader->push_back(static_cast<unsigned char>( (payloadLen & 0x00FF) >> 0 ));

		// Prepend the header to payload
		this->Payload->insert(this->Payload->begin(), relayCellHeader->begin(), relayCellHeader->end());

		// Check the size (should be exactly PAYLOAD_LEN)
		if (this->Payload->size() != this->PAYLOAD_LEN) {
			ESP_LOGW(LOGTAG, "[ERR] PrepareAsRelayCell error: the payload is %d bytes insted of %d.\n", this->Payload->size(), this->PAYLOAD_LEN);
		}

		// Calculate the digest and update relay's digest forward field
		this->FullDigest = BriandTorCryptoUtils::GetRelayCellDigest(digestForward, this->Payload);

		// Save the first 4 bytes to digest field
		for (char i = 0; i < 4; i++) {
			this->Payload->at(i + 5) = this->FullDigest->at(i);
			this->Digest += static_cast<unsigned int>( this->FullDigest->at(i) << (8*(3-i)));
		}
		
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] PrepareAsRelayCell digest is: ");
			BriandUtils::PrintByteBuffer(*this->FullDigest.get());
			printf("[DEBUG] Relay cell saved digest: %08X\n", this->Digest);
		}
	}

	void BriandTorCell::ApplyOnionSkin(BriandTorRelay& relay) {
		// Encrypt all payload with AES128CTR
		this->Payload = BriandTorCryptoUtils::AES128CTR_Encrypt(this->Payload, relay);
	}

	void BriandTorCell::PeelOnionSkin(BriandTorRelay& relay) {
		// Decrypt all payload with AES128CTR
		this->Payload = BriandTorCryptoUtils::AES128CTR_Decrypt(this->Payload, relay);
	}

	bool BriandTorCell::BuildRelayCellFromPayload(unique_ptr<mbedtls_md_context_t>& digestBackward) {
		// Set defaults
		this->StreamID = 0x0000;
		this->Recognized = 0x0000;
		this->RelayCommand = BriandTorCellRelayCommand::RELAY_END;
		this->Digest = 0x00000000;

		// Check if RELAY or RELAY_EARLY command
		if (this->Command != BriandTorCellCommand::RELAY && this->Command != BriandTorCellCommand::RELAY_EARLY) {
			ESP_LOGD(LOGTAG, "[DEBUG] Cell is not a RELAY cell! Command is %s\n", Briand::BriandUtils::BriandTorCellCommandToString(this->Command).c_str() );
			return false;
		}

		// A RELAY cell PAYLOAD contains:

		/*
			Relay command           [1 byte]
			'Recognized'            [2 bytes]
			StreamID                [2 bytes]
			Digest                  [4 bytes]
			Length                  [2 bytes]
			Data                    [Length bytes]
			Padding                 [PAYLOAD_LEN - 11 - Length bytes]
		*/

		// Check if enough payload size
		if (this->Payload->size() < 11) {
			ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell has too poor bytes.\n");
			return false;
		}

		// Get the relay command
		this->RelayCommand = static_cast<BriandTorCellRelayCommand>( this->Payload->at(0) );

		ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell command is %s\n", BriandUtils::BriandTorRelayCellCommandToString(this->RelayCommand).c_str());

		// Get the recognized field
		this->Recognized = static_cast<unsigned short>( this->Payload->at(1) << 8 );
		this->Recognized += static_cast<unsigned short>( this->Payload->at(2) );

		ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell recognized: %04X\n", this->Recognized );

		// Get the streamid field
		this->StreamID = static_cast<unsigned short>( this->Payload->at(3) << 8 );
		this->StreamID += static_cast<unsigned short>( this->Payload->at(4) );

		ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell StreamID: %04X\n", this->StreamID);

		// Get the Digest field
		this->Digest = static_cast<unsigned int>( this->Payload->at(5) << 24 );
		this->Digest += static_cast<unsigned int>( this->Payload->at(6) << 16 );
		this->Digest += static_cast<unsigned int>( this->Payload->at(7) << 8 );
		this->Digest += static_cast<unsigned int>( this->Payload->at(8) );

		ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell Digest: %08X\n", this->Digest);
		
		// Update the digest field to all zeros
		for (unsigned char i=5; i<=8; i++)
			this->Payload->at(i) = 0x00;

		// Calculate digest and update Backward digest
		this->FullDigest = BriandTorCryptoUtils::GetRelayCellDigest(digestBackward, this->Payload);
		unsigned int calculatedDigest = 0x00000000;
		calculatedDigest += static_cast<unsigned int>( this->FullDigest->at(0) << 24 );
		calculatedDigest += static_cast<unsigned int>( this->FullDigest->at(1) << 16 );
		calculatedDigest += static_cast<unsigned int>( this->FullDigest->at(2) << 8 );
		calculatedDigest += static_cast<unsigned int>( this->FullDigest->at(3) );

		// Check the digest matching
		if (this->Digest != calculatedDigest) {
			ESP_LOGD(LOGTAG, "[DEBUG] Calculated backward digest %08X does not match cell backward digest %08X.\n", this->Digest, calculatedDigest);
			return false;
		}

		// Get the length field
		unsigned short payloadLength = 0x0000;
		payloadLength = static_cast<unsigned short>( this->Payload->at(9) << 8 );
		payloadLength += static_cast<unsigned short>( this->Payload->at(10) );

		ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell real payload Length: %04X\n", payloadLength);

		// check if enough size for payload
		if (this->Payload->size() < payloadLength + 11) {
			ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell real payload length is of %u bytes but buffer has only %d\n", payloadLength + 11, this->Payload->size());
			return false;
		}

		// Remove header informations
		this->Payload->erase(this->Payload->begin(), this->Payload->begin() + 11);

		// REAL Payload, exclude padding bytes.
		this->Payload->erase(this->Payload->begin() + payloadLength, this->Payload->end());
		
		ESP_LOGD(LOGTAG, "[DEBUG] RELAY real Payload size is now %d bytes.\n", this->Payload->size());

		return true;
	}

	bool BriandTorCell::IsRelayCellRecognized(const unsigned short& streamID, const unique_ptr<mbedtls_md_context_t>& digestBackward) {
		// Check if RELAY or RELAY_EARLY command
		if (this->Command != BriandTorCellCommand::RELAY && this->Command != BriandTorCellCommand::RELAY_EARLY) {
			ESP_LOGD(LOGTAG, "[DEBUG] Cell is not a RELAY cell! Command is %s\n", Briand::BriandUtils::BriandTorCellCommandToString(this->Command).c_str() );
			return false;
		}

		// A RELAY cell PAYLOAD contains:

		/*
			Relay command           [1 byte]
			'Recognized'            [2 bytes]
			StreamID                [2 bytes]
			Digest                  [4 bytes]
			Length                  [2 bytes]
			Data                    [Length bytes]
			Padding                 [PAYLOAD_LEN - 11 - Length bytes]
		*/

		// Check if enough payload size
		if (this->Payload->size() < 11) {
			ESP_LOGD(LOGTAG, "[DEBUG] RELAY Cell has too poor bytes.\n");
			return false;
		}

		// Get the recognized field
		unsigned short cellRecognized = 0x0000;
		cellRecognized += static_cast<unsigned short>( this->Payload->at(1) << 8 );
		cellRecognized += static_cast<unsigned short>( this->Payload->at(2) );

		if (cellRecognized != 0) {
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Cell is not recognized.\n");
			}

			return false;
		}

		// Get the streamID field
		unsigned short cellStreamID = 0x0000;
		cellStreamID += static_cast<unsigned short>( this->Payload->at(3) << 8 );
		cellStreamID += static_cast<unsigned short>( this->Payload->at(4) );

		// Cell StreamID could be zero for some cells (RELAY_TRUNCATED etc.)
		if (cellStreamID != streamID && cellStreamID != 0x0000) {
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Cell StreamID does not match the expected one, unrecognized.\n");
			}

			return false;
		}

		// Get the digest field
		unsigned int cellDigest = 0x00000000;
		cellDigest += static_cast<unsigned int>( this->Payload->at(5) << 24 );
		cellDigest += static_cast<unsigned int>( this->Payload->at(6) << 16 );
		cellDigest += static_cast<unsigned int>( this->Payload->at(7) << 8 );
		cellDigest += static_cast<unsigned int>( this->Payload->at(8) );

		// Make a copy of the Payload
		auto payloadCopy = make_unique<vector<unsigned char>>();
		payloadCopy->reserve(BriandTorCell::PAYLOAD_LEN); // reserve some bytes
		payloadCopy->insert(payloadCopy->begin(), this->Payload->begin(), this->Payload->end());
		// but set the digest field to zero
		for (unsigned char i=5; i<=8; i++)
			payloadCopy->at(i) = 0x00;

		// Make a copy of the backward digest and calculate the digest without updating the relay's one.
		auto digestCopy = make_unique<mbedtls_md_context_t>();
		auto outBuf = BriandUtils::GetOneOldBuffer(digestBackward->md_info->size);
		mbedtls_md_init(digestCopy.get());
		mbedtls_md_setup(digestCopy.get(), digestBackward->md_info, 0);
		//mbedtls_md_starts(digestCopy.get());
		mbedtls_md_clone(digestCopy.get(), digestBackward.get());
		mbedtls_md_update(digestCopy.get(), payloadCopy->data(), payloadCopy->size());
		mbedtls_md_finish(digestCopy.get(), outBuf.get());
		mbedtls_md_free(digestCopy.get());

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Calculated temporary cell digest for verification: ");
			BriandUtils::PrintOldStyleByteBuffer(outBuf.get(), digestBackward->md_info->size, 0, 0);
		}

		// Finish the digest

		unsigned int cellCalculatedDigest = 0x00000000;
		cellCalculatedDigest += static_cast<unsigned int>( outBuf[0] << 24 );
		cellCalculatedDigest += static_cast<unsigned int>( outBuf[1] << 16 );
		cellCalculatedDigest += static_cast<unsigned int>( outBuf[2] << 8 );
		cellCalculatedDigest += static_cast<unsigned int>( outBuf[3] );

		if (cellCalculatedDigest != cellDigest) {
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Cell backward calculated digest %08X does not match received backward digest %08X, unrecognized.\n", cellCalculatedDigest, cellDigest);
			}

			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Relay cell passed verification!\n");

		return true;
	}

}