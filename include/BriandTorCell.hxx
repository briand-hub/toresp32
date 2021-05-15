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

#include <BriandIDFSocketTlsClient.hxx>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandTorCertificates.hxx"
#include "BriandTorRelay.hxx"

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

		// Apr 2021: The longest allowable cell payload, in bytes. (509)
		const short PAYLOAD_LEN = 509; 						

		/**
		 * Pads the payload (if needed)
		*/
		void PadPayload();

		public:

		/**
		 * Constructor
		 * @param link_protocol_version must be 1,2,3,4
		 * @param circid the CircID
		 * @param command the cell Command
		*/
		BriandTorCell(const unsigned char& link_protocol_version, const unsigned int& circid, const Briand::BriandTorCellCommand& command);

		~BriandTorCell();

		/**
		 * Append one single byte to the current payload.
		 * Warning! Do exceed PAYLOAD_LEN!
		 * @param byte Byte-Content to append
		 * @return true if success, false if exceed PAYLOAD_LEN
		*/
		bool AppendToPayload(const unsigned char& byte);

		/**
		 * Append two bytes at once to the current payload.
		 * Warning! Do exceed PAYLOAD_LEN!
		 * @param what Content to append
		 * @return true if success, false if exceed PAYLOAD_LEN
		*/
		bool AppendTwoBytesToPayload(const unsigned short& what);

		/**
		 * Append 4 bytes at once to the current payload.
		 * Warning! Do exceed PAYLOAD_LEN!
		 * @param what Content to append
		 * @return true if success, false if exceed PAYLOAD_LEN
		*/
		bool AppendFourBytesToPayload(const unsigned int& what);

		/**
		 * Append bunch bytes at once to the current payload.
		 * Warning! Do exceed PAYLOAD_LEN!
		 * @param what Content to append
		 * @return true if success, false if exceed PAYLOAD_LEN
		*/
		bool AppendBytesToPayload(vector<unsigned char>& what);

		/**
		 * Clear the current payload
		*/
		void ClearPayload();

		/**
		 * Print out the cell raw bytes to Serial output (all bytes one row)
		*/
		void PrintCellPayloadToSerial();

		/**
		 * Method to send cell over the net using the initialized and connected client secure. Cell must have Payload ready before calling!
		 * @param client Pointer to your own initialized BriandIDFSocketTlsClient, connected and ready.
		 * @param closeConnection set it to true if you want close the connection (client->end).
		 * @param expectResponse set to true if should wait for response, false instead (in this case output vector will be empty)
		 * @return Pointer to response contents
		*/
		unique_ptr<vector<unsigned char>> SendCell(unique_ptr<BriandIDFSocketTlsClient>& client, bool closeConnection = false, bool expectResponse = true);

		/**
		 * Method to rebuild cell informations starting from a buffer received. Could override link protocol version.
		 * @param buffer Pointer to the buffer
		 * @param link_protocol_version Set to <= 0 to keep the default (from constructor), or set the version (>0) to override.
		 * @return true if success, false instead.
		*/
		bool BuildFromBuffer(unique_ptr<vector<unsigned char>>& buffer, const unsigned char& link_protocol_version);

		/**
		 * @return Cell command
		*/
		Briand::BriandTorCellCommand GetCommand();

		/**
		 * @return Raw payload pointer reference (PAY(load) ATTENTION!)
		*/
		unique_ptr<vector<unsigned char>>& GetPayload();

		/**
		 * @return CircID
		*/
		unsigned int GetCircID();

		/**
		 * @return true if is a variable-length cell
		*/
		bool IsVariableLengthCell();

		/**
		 * @return Cell size in bytes (available only after SendCell or BuildFromBuffer calls)
		*/
		unsigned long int GetCellTotalSizeBytes();

		/**
		 * Method returns the highest link protocol available from a VERSION cell. Zero if non a version cell or error.
		 * @return Highest link protocol version, 0 if not a VERSION cell or error.
		*/
		unsigned short GetLinkProtocolFromVersionCell();

		/**
		 * Method sets the certificates included in a CERTS cell to the specified relay
		 * @param relay The relay where save certificates.
		 * @return true if success, false if fails.
		*/
		bool SetRelayCertificatesFromCertsCell(unique_ptr<Briand::BriandTorRelay>& relay);

		/**
		 * Method builds this cell as a fresh netinfo. Constructor must have been called
		 * with right link protocol version, CircID and command.
		 * @param yourIP the WAN IP
		*/
		void BuildAsNETINFO(const struct in_addr& yourPublicIP);

		/**
		 * Method builds this cell as a fresh CREATE2 to exchange with the specified relay. 
		 * Constructor must have been called with right link protocol version, CircID and command. 
		 * Relay will have it's ECDH context initialized after this function (if a previous one was initialize, will be lost!)
		 * @param relay The destination node
		 * @return true if success, false instead.
		*/
		bool BuildAsCREATE2(BriandTorRelay& relay);
	};

	/*
		APRIL 2021 Instructions
		The interpretation of 'Payload' depends on the type of the cell.

			VPADDING/PADDING: Payload contains padding bytes.
			CREATE/CREATE2:  Payload contains the handshake challenge.
			CREATED/CREATED2: Payload contains the handshake response.
			RELAY/RELAY_EARLY: Payload contains the relay header and relay body.
			DESTROY: Payload contains a reason for closing the circuit. (see 5.4)

		Upon receiving any other value for the command field, an OR must
		drop the cell.  Since more cell types may be added in the future, ORs
		should generally not warn when encountering unrecognized commands.
	*/
}