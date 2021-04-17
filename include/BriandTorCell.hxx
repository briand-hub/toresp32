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

using namespace std;

namespace Briand {
	
	/**
	 * This class represents a tor packet (cell)
	*/
	class BriandTorCell {
		protected:
		bool isVariableLengthCell;
		unsigned char linkProtocolVersion;

		// CircID is 4 bytes in link protocol 4+ , 2 otherwise
		// The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have CIRCID_LEN == 2 for backward compatibility.
		unsigned int CircID;
		Briand::BriandTorCellCommand Command;

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
		const short PAYLOAD_LEN = 509; 						// Apr 2021: The longest allowable cell payload, in bytes. (509)

		// The length in case of variable cells will be calculated from vector (length occupy 2 bytes)
		unique_ptr<vector<unsigned char>> Payload;

		/**
		 * Constructor
		 * @param link_protocol_version must be 1,2,3,4
		 * @param circid the CircID
		 * @param command the cell Command
		*/
		BriandTorCell(const unsigned char& link_protocol_version, const unsigned int circid, const Briand::BriandTorCellCommand& command) {
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
		}

		~BriandTorCell() {
			this->Payload->clear();
			this->Payload->resize(1);
			this->Payload.reset();
		}

		/**
		 * Method to get the buffer to be transmitted. Must set Payload BEFORE calling this method!
		 * @param bufferLength reference to write output buffer length (in bytes)
		 * @return the buffer ready to be transmitted
		*/
		unique_ptr<unsigned char[]> GetBuffer(unsigned int& bufferLength) {
			// Pad the payload
			this->PadPayload();

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

			if (this->isVariableLengthCell) {
				if (this->Command == Briand::BriandTorCellCommand::VERSIONS || this->linkProtocolVersion < 4) {
					// The versions has compatibility mode so ....
					// 2 bytes for CircID
					bufferLength = 2; 	
					// 1 byte for Command
					bufferLength += 1;  
					// 2 bytes for Length
					bufferLength += 2;  
					// just the length of Payload
					bufferLength += this->Payload->size();  
				}
				else {
					bufferLength = 4; // 4 bytes for CircID
					// 1 byte for Command
					bufferLength += 1;  
					// 2 bytes for Length
					bufferLength += 2;  
					// just the length of Payload
					bufferLength += this->Payload->size();  
				}
			}
			else {
				// For sure payload padded. just check protocol version
				// 2 or 4 bytes for CircID
				bufferLength = (this->linkProtocolVersion < 4 ? 2 : 4);
				// 1 byte for Command
				bufferLength += 1;  
				// just the length of Payload (SHOULD BE PAYLOAD_LEN)
				bufferLength += this->Payload->size();  
			}

			auto cellBuffer = make_unique<unsigned char[]>(bufferLength);

			// Build buffer 
			// (TODO: find a better way...)

			unsigned short payloadStart = 0;

			if (this->linkProtocolVersion < 4) {
				cellBuffer[0] = static_cast<unsigned char>( this->CircID & 0xFF00 );
				cellBuffer[1] = static_cast<unsigned char>( this->CircID & 0x00FF );

				cellBuffer[2] = static_cast<unsigned char>( this->Command );

				if (this->isVariableLengthCell) {
					cellBuffer[3] = static_cast<unsigned char>( this->Payload->size() & 0xFF00 );
					cellBuffer[4] = static_cast<unsigned char>( this->Payload->size() & 0x00FF );
					payloadStart = 5;
				}
				else {
					payloadStart = 3;
				}
			}
			else {
				cellBuffer[0] = static_cast<unsigned char>( this->CircID & 0xFF000000 );
				cellBuffer[1] = static_cast<unsigned char>( this->CircID & 0x00FF0000 );
				cellBuffer[2] = static_cast<unsigned char>( this->CircID & 0x0000FF00 );
				cellBuffer[3] = static_cast<unsigned char>( this->CircID & 0x000000FF );

				cellBuffer[4] = static_cast<unsigned char>( this->Command );

				if (this->isVariableLengthCell) {
					cellBuffer[5] = static_cast<unsigned char>( this->Payload->size() & 0xFF00 );
					cellBuffer[6] = static_cast<unsigned char>( this->Payload->size() & 0x00FF );
					payloadStart = 7;
				}
				else {
					payloadStart = 5;
				}
			}

			for (unsigned short i = 0; i<this->Payload->size(); i++) {
				cellBuffer[i + payloadStart] = static_cast<unsigned char>( this->Payload->at(i) );
			}

			return std::move(cellBuffer);
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