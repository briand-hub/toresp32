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

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>

#include <iostream>
#include <memory>
#include <sstream>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorCell.hxx"

using namespace std;

namespace Briand {

	/**
	 * This class manage a single Tor circuit 
	*/
	class BriandTorCircuit {
		protected:
		unique_ptr<Briand::BriandTorRelaySearcher> relaySearcher;
		bool isBuilt;		// has been built
		bool isClean; 		// not used for any traffic
		bool isClosing;		// it is currently closing
		bool isClosed;		// it is closed (call destroyer and free RAM!!)
		unsigned int CIRCID;

		public:
		unique_ptr<Briand::BriandTorRelay> guardNode;
		unique_ptr<Briand::BriandTorRelay> middleNode;
		unique_ptr<Briand::BriandTorRelay> exitNode;

		BriandTorCircuit() {
			guardNode = nullptr;
			middleNode = nullptr;
			exitNode = nullptr;
			relaySearcher = nullptr;

			this->isBuilt = false;
			this->isClean = false;
			this->isClosing = false;
			this->isClosed = false;
		}

		~BriandTorCircuit() {
			if (guardNode != nullptr) guardNode.reset();
			if (middleNode != nullptr) middleNode.reset();
			if (exitNode != nullptr) exitNode.reset();
			if (relaySearcher != nullptr) relaySearcher.reset();
		}

		/**
		 * Builds a new circuit 
		 * @param maxTentatives maximum attempts to find nodes and build the circuit.
		 * @return true on success
		*/ 
		bool BuildCircuit(const unsigned short maxTentatives = 10) {
			// Prepare for search
			this->relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();

			// Search for nodes to build a path: 
			// may take time due to request/response time plus delays (needed in order to keep safe ESP32 watchdog!)

			/*	RULES for choosing path on April 2021 (https://gitweb.torproject.org/torspec.git/tree/path-spec.txt)

				- We do not choose the same router twice for the same path.
				- We do not choose any router in the same family as another in the same
				path. (Two routers are in the same family if each one lists the other
				in the "family" entries of its descriptor.)
				- We do not choose more than one router in a given /16 subnet
				(unless EnforceDistinctSubnets is 0).
				- We don't choose any non-running or non-valid router unless we have
				been configured to do so. By default, we are configured to allow
				non-valid routers in "middle" and "rendezvous" positions.
				- If we're using Guard nodes, the first node must be a Guard (see 5
				below)
			*/

			if (DEBUG) Serial.println("[DEBUG] Starting relay search.");

			unsigned short attempts_made = 0;
			bool stepDone = false;

			if (DEBUG) Serial.println("[DEBUG] Starting search for guard node.");

			while (attempts_made < maxTentatives && !stepDone) {
				auto tentative = this->relaySearcher->GetGuardRelay();
				
				if (tentative != nullptr) {
					this->guardNode = std::move(tentative);
					stepDone = true;
					if (DEBUG) Serial.println("[DEBUG] Guard node OK.");
				}
				else {
					if (DEBUG) Serial.println("[DEBUG] Retry search for guard node.");
					attempts_made++;
					delay(2000); // wait 2 seconds before doing a new request
				}
			}

			if (attempts_made == maxTentatives && !stepDone) return false;

			attempts_made = 0;
			stepDone = false;

			if (DEBUG) Serial.println("[DEBUG] Starting search for middle node.");

			while (attempts_made < maxTentatives && !stepDone) {
				auto tentative = this->relaySearcher->GetMiddleRelay();
				
				if (tentative != nullptr) {

					//
					// TODO : test not in the same family!
					//

					this->middleNode = std::move(tentative);
					stepDone = true;
					if (DEBUG) Serial.println("[DEBUG] Middle node OK.");
				}
				else {
					if (DEBUG) Serial.println("[DEBUG] Retry search for middle node.");
					attempts_made++;
					delay(2000); // wait 2 seconds before doing a new request
				}
			}
			
			if (attempts_made == maxTentatives && !stepDone) return false;

			attempts_made = 0;
			stepDone = false;

			if (DEBUG) Serial.println("[DEBUG] Starting search for exit node.");

			while (attempts_made < maxTentatives && !stepDone) {
				auto tentative = this->relaySearcher->GetExitRelay();
				
				if (tentative != nullptr) {

					//
					// TODO : test not in the same family!
					//

					this->exitNode = std::move(tentative);
					stepDone = true;
					if (DEBUG) Serial.println("[DEBUG] Exit node OK.");
				}
				else {
					if (DEBUG) Serial.println("[DEBUG] Retry search for exit node.");
					attempts_made++;
					delay(2000); // wait 2 seconds before doing a new request
				}
			}
			
			if (attempts_made == maxTentatives && !stepDone) return false;

			if (DEBUG) Serial.println("[DEBUG] All nodes ready, start VERSION to guard.");

			// All nodes found! Free some RAM
			this->relaySearcher.reset();

			// Now start to build the path

			// Prepare client for communicate
			auto wifiClient = make_unique<WiFiClient>();
			
			// Choose random CircID

			// TODO: do not understand:

			// To prevent CircID collisions, when one node sends a CREATE/CREATE2
   			// cell to another, it chooses from only one half of the possible
   			// values based on the ORs' public identity keys.

			// The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have CIRCID_LEN == 2 for backward compatibility.

			this->CIRCID = ( Briand::BriandUtils::GetRandomByte() << 8 ) + Briand::BriandUtils::GetRandomByte();

			// 1. Send a VERSION the guard

			if ( wifiClient->connect(this->guardNode->GetHost().c_str(), this->guardNode->GetPort()) ) {
				unique_ptr<Briand::BriandTorCell> tempCell = make_unique<Briand::BriandTorCell>(0, this->CIRCID, Briand::BriandTorCellCommand::VERSIONS);	

				/*
				The payload in a VERSIONS cell is a series of big-endian two-byte
				integers.  Both parties MUST select as the link protocol version the
				highest number contained both in the VERSIONS cell they sent and in the
				versions cell they received.  If they have no such version in common,
				they cannot communicate and MUST close the connection.  Either party MUST
				close the connection if the versions cell is not well-formed (for example,
				if it contains an odd number of bytes).
				*/

				if (DEBUG) Serial.printf("[DEBUG] Client connected to %s on port %d\n", this->guardNode->GetHost().c_str(), this->guardNode->GetPort());
				
				tempCell->Payload->push_back(0x00);
				tempCell->Payload->push_back(0x03); // link version 3
				tempCell->Payload->push_back(0x00);
				tempCell->Payload->push_back(0x04); // or link version 4

				unsigned int bufferSize = 0;
				auto cellBuffer = tempCell->GetBuffer(bufferSize);

				if (DEBUG) Serial.println("[DEBUG] CELL BYTES:");
				if (DEBUG) Briand::BriandUtils::printByteBuffer(cellBuffer.get(), bufferSize);

				if (DEBUG) Serial.printf("[DEBUG] Sending cell of %u bytes... ", bufferSize);

				wifiClient->write( cellBuffer.get(), bufferSize );

				cellBuffer.reset();
				tempCell.reset();

				if (DEBUG) Serial.print("sent!\n");

				// Wait response
				while (wifiClient->connected() && !wifiClient->available()) {
					delay(10);
				}

				// Got response or disconnect
				if (wifiClient->connected()) {
					if (DEBUG) Serial.print("[DEBUG] Guard response to VERSION, size ");

					auto respBuffer = make_unique<vector<unsigned char>>();

					while ( wifiClient->available() > 0) {
						respBuffer->push_back( wifiClient->read() );
					}

					if (DEBUG) Serial.printf("%d bytes:\n", respBuffer->size());
					if (DEBUG) Briand::BriandUtils::printByteBuffer( *respBuffer.get() );
				}
				else {
					if (VERBOSE) Serial.println("[ERR] Error on receiving VERSION response from Guard.");
				}

			}
			else {
				if (VERBOSE) Serial.println("[ERR] Error on sending first VERSION to Guard.");
			}

			
			



			//
			// TODO
			//


			// Circuit is now OK!

			this->isBuilt = true;
			this->isClean = true;

			return true;
		}
	};
}