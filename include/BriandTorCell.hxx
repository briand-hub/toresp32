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

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandTorCertificate.hxx"

using namespace std;

namespace Briand {
	
	/**
	 * This class represents a tor packet (cell)
	*/
	class BriandTorCell {
		protected:
		bool isVariableLengthCell;
		unsigned short linkProtocolVersion;
		unsigned long cellTotalSizeBytes;

		// CircID is 4 bytes in link protocol 4+ , 2 otherwise
		// The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have CIRCID_LEN == 2 for backward compatibility.
		unsigned int CircID;
		Briand::BriandTorCellCommand Command;

		// The length in case of variable cells will be calculated from vector (length occupy 2 bytes)
		unique_ptr<vector<unsigned char>> Payload;

		const short PAYLOAD_LEN = 509; 						// Apr 2021: The longest allowable cell payload, in bytes. (509)

		/**
		 * Pads the payload (if needed)
		*/
		void PadPayload() {
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
				while (this->Payload->size() < this->PAYLOAD_LEN)
					this->Payload->push_back( Briand::BriandUtils::GetRandomByte() );
			}
			else {
				// May...?
				while (this->Payload->size() < this->PAYLOAD_LEN)
					this->Payload->push_back( 0x00 );
			}
		}

		public:

		/**
		 * Constructor
		 * @param link_protocol_version must be 1,2,3,4
		 * @param circid the CircID
		 * @param command the cell Command
		*/
		BriandTorCell(const unsigned char& link_protocol_version, const unsigned int& circid, const Briand::BriandTorCellCommand& command) {
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

			this->cellTotalSizeBytes = 0;
		}

		~BriandTorCell() {
			this->Payload->clear();
			this->Payload->resize(1);
			this->Payload.reset();
		}

		/**
		 * Append one single byte to the current payload.
		 * Warning! Do exceed PAYLOAD_LEN!
		 * @param byte Byte-Content to append
		 * @return true if success, false if exceed PAYLOAD_LEN
		*/
		bool AppendToPayload(const unsigned char& byte) {
			if (this->Payload->size() + 1 > this->PAYLOAD_LEN)
				return false;

			this->Payload->push_back(byte);
			return true;
		}

		/**
		 * Clear the current payload
		*/
		void ClearPayload() {
			this->Payload->clear();
		}

		/**
		 * Print out the cell raw bytes to Serial output, group 8 bytes per row
		*/
		void PrintCellPayloadToSerial() {
			Briand::BriandUtils::PrintByteBuffer( *(this->Payload.get()) );
		}

		/**
		 * Method to send cell over the net using the initialized and connected client secure.
		 * @param client Pointer to your own initialized WiFiClientSecure, connected and ready.
		 * @param closeConnection set it to true if you want close the connection (client->end).
		 * @return Pointer to response contents
		*/
		unique_ptr<vector<unsigned char>> SendCell(unique_ptr<WiFiClientSecure>& client, bool closeConnection = false) {
			// Prepare the cell header and pad payload if necessary
			auto cellBuffer = make_unique<vector<unsigned char>>();

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
				cellBuffer->push_back( static_cast<unsigned char>( this->CircID & 0xFF00 ) );
				cellBuffer->push_back( static_cast<unsigned char>( this->CircID & 0x00FF ) );
			}
			else if (this->linkProtocolVersion >= 4) {
				// CircID is 4 bytes
				cellBuffer->push_back( static_cast<unsigned char>( this->CircID & 0xFF000000 ) );
				cellBuffer->push_back( static_cast<unsigned char>( this->CircID & 0x00FF0000 ) );
				cellBuffer->push_back( static_cast<unsigned char>( this->CircID & 0x0000FF00 ) );
				cellBuffer->push_back( static_cast<unsigned char>( this->CircID & 0x000000FF ) );
			}

			// 1 byte for Command, always
			cellBuffer->push_back( static_cast<unsigned char>(this->Command) );

			// If variable-length cell, 2 bytes must be added, containing payload len
			if (this->isVariableLengthCell) {
				cellBuffer->push_back( static_cast<unsigned char>( this->Payload->size() & 0xFF00 ) );
				cellBuffer->push_back( static_cast<unsigned char>( this->Payload->size() & 0x00FF ) );
			}

			// Pad payload (will check itself if it is needed)
			this->PadPayload();

			// Append payload to cellBuffer
			cellBuffer->insert(cellBuffer->end(), this->Payload->begin(), this->Payload->end());

			this->cellTotalSizeBytes = cellBuffer->size();

			if (DEBUG) Serial.printf("[DEBUG] %s Cell of %d bytes is going to be sent. Contents:\n", Briand::BriandUtils::BriandTorCellCommandToString(this->Command).c_str(), cellBuffer->size());
			if (DEBUG) Briand::BriandUtils::PrintByteBuffer( *(cellBuffer.get()), 128 );

			// That's all, send cell through network!
			auto response = Briand::BriandNet::RawSecureRequest(client, cellBuffer, true, closeConnection); // clear cell buffer after request to save ram.
			cellBuffer.reset(); // free ram
			return std::move(response);
		}

		/**
		 * Method to rebuild cell informations starting from a buffer received. Could override link protocol version.
		 * @param buffer Pointer to the buffer
		 * @param link_protocol_version Set to <= 0 to keep the default (from constructor), or set the version (>0) to override.
		 * @return true if success, false instead.
		*/
		bool BuildFromBuffer(unique_ptr<vector<unsigned char>>& buffer, const unsigned char& link_protocol_version) {
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
				if (DEBUG) Serial.println("[DEBUG] Insufficient length (less than 5 bytes).");
				return false;
			}

			unsigned short nextFrom = 0;

			// CircID
			if (this->linkProtocolVersion < 4) {
				// CircID is 2 bytes, VERSION cells are always 2 bytes
				if (DEBUG) Serial.printf("[DEBUG] Link protocol <4 (Ver.%u)\n", this->linkProtocolVersion);
				this->CircID += static_cast<unsigned int>(buffer->at(0) << 8);
				this->CircID += static_cast<unsigned int>(buffer->at(1));
				nextFrom = 2;
				cellTotalSizeBytes += 2;
			}
			else {
				// CircID is 4 bytes
				if (DEBUG) Serial.printf("[DEBUG] Link protocol >=4. (Ver. %u)\n", this->linkProtocolVersion);
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

			if (DEBUG) Serial.printf("[DEBUG] Cell command is %s\n", Briand::BriandUtils::BriandTorCellCommandToString(this->Command).c_str() );

			// Command => I know if is variable length cell
			if (this->Command == Briand::BriandTorCellCommand::VERSIONS || static_cast<unsigned int>(this->Command) >= 128) 
				this->isVariableLengthCell = true;

			// If variable length cell then I must have 2 bytes for Length and [Length] bytes more
			if(this->isVariableLengthCell && (buffer->size() - nextFrom) < 2) {
				if (DEBUG) Serial.println("[DEBUG] Variable-length cell has insufficient length.");
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
					if (DEBUG) Serial.println("[DEBUG] Variable-length cell has insufficient payload length.");
					return false;
				}

				// Read all payload
				this->Payload->insert(this->Payload->begin(), buffer->begin() + nextFrom, buffer->begin() + nextFrom + length);

				if (DEBUG) {
					Serial.print("[DEBUG] Variable-length cell payload: ");
					Briand::BriandUtils::PrintByteBuffer( *(this->Payload.get()), 128 );
				} 
			}
			else {
				// All the rest, for a maximum of PAYLOAD_LEN, is payload
				this->Payload->insert(this->Payload->begin(), buffer->begin() + nextFrom, buffer->begin() + nextFrom + PAYLOAD_LEN);
				if (DEBUG) Serial.printf("[DEBUG] Fixed cell payload of %d bytes.\n", this->Payload->size());
			}

			cellTotalSizeBytes += this->Payload->size();

			return true;
		}

		/**
		 * @return Cell command
		*/
		Briand::BriandTorCellCommand GetCommand() {
			return this->Command;
		}

		/**
		 * @return Raw payload pointer reference (PAY(load) ATTENTION!)
		*/
		unique_ptr<vector<unsigned char>>& GetPayload() {
			return this->Payload;
		}

		/**
		 * @return Link protocol version
		*/
		unsigned int GetCircID() {
			return this->CircID;
		}

		/**
		 * @return true if is a variable-length cell
		*/
		bool IsVariableLengthCell() {
			return this->isVariableLengthCell;
		}

		/**
		 * @return Cell size in bytes (available only after SendCell or BuildFromBuffer calls)
		*/
		unsigned long int GetCellTotalSizeBytes() {
			return this->cellTotalSizeBytes;
		}

		/**
		 * Method returns the highest link protocol available from a VERSION cell. Zero if non a version cell or error.
		 * @return Highest link protocol version, 0 if not a VERSION cell or error.
		*/
		unsigned short GetLinkProtocolFromVersionCell() {
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

		/**
		 * Method sets the certificates included in a CERTS cell to the specified relay
		 * @param relay The relay where save certificates.
		 * @return true if success, false if fails.
		*/
		bool SetRelayCertificatesFromCertsCell(unique_ptr<Briand::BriandTorRelay>& relay) {
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
					if (DEBUG) Serial.printf("[DEBUG] Invalid CERTS cell content (%d is not a valid range certType).\n", certType);
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

				if (DEBUG) Serial.printf("[DEBUG] Certificate %u (of %u) is certType %u.\n", curCert+1, NCerts, certType);

				// 2 bytes for length
				unsigned short certLen = 0;
				certLen += static_cast<unsigned short>(this->Payload->at(startIndex) << 8);
				certLen += static_cast<unsigned short>(this->Payload->at(startIndex+1));
				startIndex += 2;

				if (DEBUG) Serial.printf("[DEBUG] Certificate len is %u bytes.\n", certLen);

				// Payload should contain at least this length
				if (this->Payload->size() - startIndex < certLen) {
					if (DEBUG) Serial.println("[DEBUG] Invalid CERTS cell content size.");
					return false;
				}

				auto edBuf = make_unique<vector<unsigned char>>(); // temp buffer in case of ed25519 certs (must be built on contructor)

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

	};

	/*
		APRIL 2021 Instructions
		The interpretation of 'Payload' depends on the type of the cell.

			VPADDING/PADDING:
					Payload contains padding bytes.
			CREATE/CREATE2:  Payload contains the handshake challenge.
			CREATED/CREATED2: Payload contains the handshake response.
			RELAY/RELAY_EARLY: Payload contains the relay header and relay body.
			DESTROY: Payload contains a reason for closing the circuit.
					(see 5.4)

		Upon receiving any other value for the command field, an OR must
		drop the cell.  Since more cell types may be added in the future, ORs
		should generally not warn when encountering unrecognized commands.
	*/
}