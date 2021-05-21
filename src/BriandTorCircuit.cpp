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

#include "BriandTorCircuit.hxx"


#include <time.h>


#include <iostream>
#include <memory>
#include <sstream>

#include <BriandIDFSocketTlsClient.hxx>

#include "BriandDefines.hxx"
#include "BriandTorDefinitions.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorCell.hxx"

using namespace std;

namespace Briand {

	void BriandTorCircuit::Cleanup() {
		if (this->relaySearcher != nullptr) this->relaySearcher.reset();
		if (this->sClient != nullptr) {
			// close connetion if active
			if (this->sClient->IsConnected())
				this->sClient->Disconnect();
			this->sClient.reset();
		}
	}

	bool BriandTorCircuit::FindAndPopulateRelay(const unsigned char& relayType) {
		string relayS;

		if (DEBUG) {
			
			switch (relayType) {
				case 0: relayS = "guard"; break;
				case 1: relayS = "middle"; break;
				case 2: relayS = "exit"; break;
				default: relayS = to_string(relayType) + "(?)";
			}
		}

		printf("[DEBUG] Starting search for %s node.\n", relayS.c_str());

		bool done = false;
		
		unique_ptr<Briand::BriandTorRelay> tentative = nullptr;

		if (relayType == 0) {
			tentative = this->relaySearcher->GetGuardRelay();
		}
		else if (relayType == 1) {
			if (this->guardNode != nullptr) 
				tentative = this->relaySearcher->GetMiddleRelay(*this->guardNode->address.get());
			else
				tentative = this->relaySearcher->GetMiddleRelay("");
		} 
		else if (relayType == 2) {
			if (this->guardNode != nullptr && this->middleNode != nullptr)
				tentative = this->relaySearcher->GetExitRelay(*this->guardNode->address.get(), *this->middleNode->address.get());
			else
				tentative = this->relaySearcher->GetExitRelay("", "");
		} 
		
		if (tentative != nullptr) {
			// Fetch relay descriptors

			if (DEBUG) printf("[DEBUG] Retrieving descriptors for %s node...\n", relayS.c_str());

			if (tentative->FetchDescriptorsFromAuthority()) {

				if (relayType == 0) this->guardNode = std::move(tentative);
				else if (relayType == 1) this->middleNode = std::move(tentative);
				else if (relayType == 2) this->exitNode = std::move(tentative);

				done = true;
				if (DEBUG) printf("[DEBUG] %s node ok.\n", relayS.c_str());
			}
			else {
				if (DEBUG) printf("[DEBUG] Retrieving descriptors for %s node FAILED\n", relayS.c_str());
			}
		}

		if (!done && VERBOSE) printf("[ERR] FAIL to get a valid %s node.\n", relayS.c_str());

		return done;
	}

	bool BriandTorCircuit::StartInProtocolWithGuard(bool authenticateSelf /* = false*/) {
		// Choose a first, random CircID (does not matter here, see CREATE2)
		// The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have CIRCID_LEN == 2 for backward compatibility.

		this->CIRCID = ( Briand::BriandUtils::GetRandomByte() << 8 ) + Briand::BriandUtils::GetRandomByte();

		if(DEBUG) printf("[DEBUG] Temporary CircID = 0x%04X\n", this->CIRCID);

		unique_ptr<Briand::BriandTorCell> tempCell = nullptr;
		unique_ptr<vector<unsigned char>> tempCellResponse = nullptr;

		/*
			When the in-protocol handshake is used, the initiator sends a
			VERSIONS cell to indicate that it will not be renegotiating.  The
			responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
			initiator the certificates it needs to learn the responder's
			identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
			as part of its answer if it chooses to authenticate, and a NETINFO
			cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
			whether the responder is correctly authenticated.  At this point the
			initiator behaves differently depending on whether it wants to
			authenticate or not. If it does not want to authenticate, it MUST
			send a NETINFO cell.  If it does want to authenticate, it MUST send a
			CERTS cell, an AUTHENTICATE cell (4.4), and a NETINFO.  When this
			handshake is in use, the first cell must be VERSIONS, VPADDING, or
			AUTHORIZE, and no other cell type is allowed to intervene besides
			those specified, except for VPADDING cells.
		*/

		// Start with VERSIONS (+CERTS +AUTH_CHALLENGE +NETINFO) 
		// and authenticate myself (not for now, TODO )

		
		/*
			The payload in a VERSIONS cell is a series of big-endian two-byte
			integers.  Both parties MUST select as the link protocol version the
			highest number contained both in the VERSIONS cell they sent and in the
			versions cell they received.  If they have no such version in common,
			they cannot communicate and MUST close the connection.  Either party MUST
			close the connection if the versions cell is not well-formed (for example,
			if it contains an odd number of bytes).
		*/

		// Send a VERSION the guard

		if (DEBUG) printf("[DEBUG] Sending first VERSION to guard.\n");

		tempCell = make_unique<Briand::BriandTorCell>(0, this->CIRCID, Briand::BriandTorCellCommand::VERSIONS);

		// link version 4 at least please!!!
		tempCell->AppendTwoBytesToPayload(0x0004);
		tempCell->AppendTwoBytesToPayload(0x0005);

		tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell.reset();

		if (tempCellResponse->size() == 0) {
			if (VERBOSE) printf("[ERR] Error on sending first VERSION to Guard.\n");
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Cell response! :-D Contents (first 32 bytes): ");
		if (DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );
		
		// The response contents should have a lot of informations.

		// First is a version cell containing valid linkprotocols to use.
		// The cell is always backward-compatible

		// start an empty cell to build with buffer

		tempCell =  make_unique<Briand::BriandTorCell>(0, 0, Briand::BriandTorCellCommand::PADDING); 
		tempCell->BuildFromBuffer(tempCellResponse, 2); // Link protocol is always 2 for VERSION
		this->LINKPROTOCOLVERSION = tempCell->GetLinkProtocolFromVersionCell();

		if (this->LINKPROTOCOLVERSION == 0) {
			if (VERBOSE) printf("[ERR] Error on receiving first VERSION from Guard, unable to negotiate link protocol version.\n");
			this->Cleanup();
			return false;
		}
		else if (this->LINKPROTOCOLVERSION < 4) {
			if (VERBOSE) printf("[ERR] Guard has an old link protocol (version %d but required >= 4).\n", this->LINKPROTOCOLVERSION);
			this->Cleanup();
			return false;
		}
		else if (DEBUG) {
			printf("[DEBUG] Link protocol version %d negotiation SUCCESS.\n", this->LINKPROTOCOLVERSION);
		}

		// The next part of buffer should be a CERTS cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		if (DEBUG) printf("[DEBUG] Next chunk (first 32 bytes printed): ");
		if (DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::CERTS) {
			if (VERBOSE) printf("[ERR] Error, expected CERTS cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Got CERTS cell!\n");
		
		if (! tempCell->SetRelayCertificatesFromCertsCell(this->guardNode) ) {
			if (VERBOSE) printf("[ERR] CERTS cell seems not valid.\n");
			this->Cleanup();
			return false;
		}

		if (DEBUG) {
			printf("[DEBUG] Guard has %d certifcates loaded.\n", this->guardNode->GetCertificateCount());
			this->guardNode->PrintAllCertificateShortInfo();
		} 

		if ( ! this->guardNode->ValidateCertificates() ) {
			if (VERBOSE) printf("[ERR] CERTS cell received has invalid certificates.\n");
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] CERTS cell certificates validation succeded.\n");

		// The next part of buffer should be a AUTH_CHALLENGE cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		// AUTH_CHALLENGE is used for authenticate, might not do that.

		if (DEBUG) printf("[DEBUG] Next chunk (first 32 bytes printed): ");
		if (DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::AUTH_CHALLENGE) {
			if (VERBOSE) printf("[ERR] Error, expected AUTH_CHALLENGE cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Got AUTH_CHALLENGE cell!\n");

		if (DEBUG) printf("[DEBUG] WARNING: AUTH_CHALLENGE cell is not handled at moment from this version.\n");
		// TODO dont't mind for now..

		// The next part of buffer should be a NETINFO cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::NETINFO) {
			if (VERBOSE) printf("[ERR] Error, expected NETINFO cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Got NETINFO cell!\n");

		if (DEBUG) printf("[DEBUG] Info: this version do not check or handle incoming NETINFO cell.\n");
		// TODO dont't mind for now..

		if (DEBUG) printf("[DEBUG] Got all cells needed for handshake :-)\n");

		// The next part of buffer needs to be ignored, could be cleared and save RAM.
		// WARNING: for answer to auth all bytes received must be kept!
		tempCellResponse.reset();
		tempCell.reset();

		// After authentication....

		//
		// TODO ?
		// 

		// Answer with NETINFO CELL

		if (DEBUG) printf("[DEBUG] Sending NETINFO cell to guard.\n");

		tempCell = make_unique<BriandTorCell>( this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::NETINFO );
		struct in_addr public_ip;
		inet_aton(BriandUtils::BriandGetPublicIPFromIfConfigMe().c_str(), &public_ip);
		tempCell->BuildAsNETINFO( public_ip );

		if (DEBUG) {
			printf("[DEBUG] NETINFO cell payload to send: ");
			tempCell->PrintCellPayloadToSerial();
		} 

		tempCellResponse = tempCell->SendCell(this->sClient, false, false); // Last false: do not expect a response

		printf("[DEBUG] NETINFO cell sent.\n");

		// Freee
		tempCell.reset();
		tempCellResponse.reset();
		
		return true;
	}

	bool BriandTorCircuit::Create2() {
		if (DEBUG) printf("[DEBUG] Sending CREATE2 cell to guard.\n");

		/*					
			Users set up circuits incrementally, one hop at a time. To create a
			new circuit, OPs send a CREATE/CREATE2 cell to the first node, with
			the first half of an authenticated handshake; that node responds with
			a CREATED/CREATED2 cell with the second half of the handshake. To
			extend a circuit past the first hop, the OP sends an EXTEND/EXTEND2
			relay cell (see section 5.1.2) which instructs the last node in the
			circuit to send a CREATE/CREATE2 cell to extend the circuit.
		*/

		auto tempCell = make_unique<Briand::BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::CREATE2);
		
		if (!tempCell->BuildAsCREATE2(*this->guardNode.get())) {
			if (DEBUG) printf("[DEBUG] Failed on building cell CREATE2.\n");
			return false;
		}

		if (DEBUG) printf("[DEBUG] CREATE2 sent. Waiting for CREATED2.\n");
		auto tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);
		
		if (!tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION)) {
			if (VERBOSE) printf("[ERR] Error, response cell had invalid bytes (failed to build from buffer).\n");
			this->Cleanup();
			return false;
		}
		
		// If a DESTROY given, tell me why
		if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
			if (VERBOSE) printf("[ERR] Error, DESTROY received! Reason = 0x%02X\n", tempCell->GetPayload()->at(0));
			this->Cleanup();
			return false;
		}

		if (tempCell->GetCommand() != BriandTorCellCommand::CREATED2) {
			if (VERBOSE) printf("[ERR] Error, response contains %s cell instead of CREATED2. Failure.\n", BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Got CREATED2, payload:");
		if (DEBUG) tempCell->PrintCellPayloadToSerial();

		// Finish the handshake!
		if (!this->guardNode->FinishHandshake(tempCell->GetPayload())) {
			if (VERBOSE) printf("[ERR] Error on concluding handshake!\n");
			// From now... always destroy
			this->TearDown();
			this->Cleanup();
			return false;
		}

		// Free buffers
		tempCell.reset();
		tempCellResponse.reset();

		return true;
	}

	bool BriandTorCircuit::Extend2(bool exitNode) {
		if (DEBUG) printf("[DEBUG] Sending EXTEND2 cell to guard.\n");

		// EXTEND2 is a RELAY cell! (RELAY_EARLY since link protocol v2)

		auto tempCell = make_unique<Briand::BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::RELAY_EARLY);
		
		if (exitNode) {
			if (!tempCell->BuildAsEXTEND2(*this->exitNode.get())) {
				if (DEBUG) printf("[DEBUG] Failed on building cell EXTEND2 to exit.\n");
				return false;
			}
		}
		else {
			if (!tempCell->BuildAsEXTEND2(*this->middleNode.get())) {
				if (DEBUG) printf("[DEBUG] Failed on building cell EXTEND2 to middle.\n");
				return false;
			}
		}

		// Prepare a StreamID of all zeros (relay commands with [control] use all-zero streamid!)
		unsigned short streamID = 0x0000;

		// do {
		// 	streamID += (BriandUtils::GetRandomByte() << 8);
		// 	streamID += (BriandUtils::GetRandomByte() << 0);
		// } while (streamID == 0x0000); 

		if (DEBUG) printf("[DEBUG] StreamID is: %04X\n", streamID);

		// After building the main contents, prepare it as a relay cell
		if (exitNode) {
			tempCell->PrepareAsRelayCell(BriandTorCellRelayCommand::RELAY_EXTEND2, streamID, this->middleNode->KEY_ForwardDigest_Df);
		}
		else {
			tempCell->PrepareAsRelayCell(BriandTorCellRelayCommand::RELAY_EXTEND2, streamID, this->guardNode->KEY_ForwardDigest_Df);
		}

		if (DEBUG) {
			printf("[DEBUG] EXTEND2 contents before encryption: ");
			tempCell->PrintCellPayloadToSerial();
		}

		// Then encrypt
		if (exitNode) {
			// Encrypt with middle key
			tempCell->ApplyOnionSkin(this->middleNode->KEY_Forward_Kf);
			if (DEBUG) printf("[DEBUG] Applied MIDDLE onion skin.\n");
			// Encrypt with guard key
			tempCell->ApplyOnionSkin(this->guardNode->KEY_Forward_Kf);
			if (DEBUG) printf("[DEBUG] Applied GUARD onion skin.\n");
		}
		else {
			// Encrypt with guard key
			tempCell->ApplyOnionSkin(this->guardNode->KEY_Forward_Kf);
			if (DEBUG) printf("[DEBUG] Applied GUARD onion skin.\n");
		}

		if (DEBUG) printf("[DEBUG] EXTEND2 sent. Waiting for EXTENDED2.\n");
		auto tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);
		
		if (!tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION)) {
			if (VERBOSE) printf("[ERR] Error, response cell had invalid bytes (failed to build from buffer).\n");
			this->Cleanup();
			return false;
		}
		
		// If a DESTROY given, tell me why
		if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
			if (VERBOSE) printf("[ERR] Error, DESTROY received! Reason = 0x%02X\n", tempCell->GetPayload()->at(0));
			this->Cleanup();
			return false;
		}

		if (tempCell->GetCommand() != BriandTorCellCommand::RELAY) {
			if (VERBOSE) printf("[ERR] Error, response contains %s cell instead of RELAY. Failure.\n", BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Got RELAY cell, payload:");
		if (DEBUG) tempCell->PrintCellPayloadToSerial();

	
		// Decrypt payload
		if (exitNode) {
			tempCell->PeelOnionSkin(this->middleNode->KEY_Backward_Kb);
			if (DEBUG) printf("[DEBUG] Removed MIDDLE onion skin.\n");
			tempCell->PeelOnionSkin(this->guardNode->KEY_Backward_Kb);
			if (DEBUG) printf("[DEBUG] Removed GUARD onion skin.\n");
		}
		else {
			tempCell->PeelOnionSkin(this->guardNode->KEY_Backward_Kb);
			if (DEBUG) printf("[DEBUG] Removed GUARD onion skin.\n");
		}

		// Finish the handshake!
		/* The payload of an EXTENDED2 cell is the same as the payload of a CREATED2 cell */
		if (!this->guardNode->FinishHandshake(tempCell->GetPayload())) {
			if (VERBOSE) printf("[ERR] Error on concluding handshake!\n");
			// Always destroy if fails
			this->TearDown();
			this->Cleanup();
			return false;
		}

		// Free buffers
		tempCell.reset();
		tempCellResponse.reset();

		return true;
	}

	BriandTorCircuit::BriandTorCircuit() {
		this->guardNode = nullptr;
		this->middleNode = nullptr;
		this->exitNode = nullptr;
		this->relaySearcher = nullptr;

		this->isBuilt = false;
		this->isCreating = false;
		this->isClean = false;
		this->isClosing = false;
		this->isClosed = false;
		this->createdOn = 0;

		this->CIRCID = 0;
		this->LINKPROTOCOLVERSION = 0;
		
		this->sClient = nullptr;
	}

	BriandTorCircuit::~BriandTorCircuit() {
		// If it was previously created or a tentative was in place, tear down the previous.
		if ( (this->isCreating || this->isBuilt) && !(this->isClosed || this->isClosing) ) {
			this->TearDown();
		}

		if (!this->isClosed) {
			this->TearDown();
		}

		if (this->sClient != nullptr) {
			// close connetion if active
			if (this->sClient->IsConnected())
				this->sClient->Disconnect();
			this->sClient.reset();
		}

		if (this->guardNode != nullptr) this->guardNode.reset();
		if (this->middleNode != nullptr) this->middleNode.reset();
		if (this->exitNode != nullptr) this->exitNode.reset();
		if (this->relaySearcher != nullptr) this->relaySearcher.reset();
	}

	bool BriandTorCircuit::BuildCircuit(bool forceTorCacheRefresh /* = false*/) {
		// If it was previously created or a tentative was in place, tear down the previous.
		if ( (this->isCreating || this->isBuilt) && !(this->isClosed || this->isClosing) ) {
			this->TearDown();
		}

		if (forceTorCacheRefresh) {
			auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
			relaySearcher->InvalidateCache(true); // invalidate and rebuild the cache
		}

		// Refresh
		this->isBuilt = false;
		this->isClean = false;
		this->isClosed = true;
		this->isClosing = false;
		this->isCreating = false;
		
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

		if (DEBUG) printf("[DEBUG] Starting relay search.\n");

		if (!this->FindAndPopulateRelay(0)) return false; // GUARD

		if (DEBUG) this->guardNode->PrintRelayInfo();

		if (DEBUG) printf("[DEBUG] Starting relay search for middle node.\n");
		
		if (!this->FindAndPopulateRelay(1)) return false; // MIDDLE

		if (DEBUG) this->middleNode->PrintRelayInfo();
		
		if (DEBUG) printf("[DEBUG] Starting relay search for exit node.\n");

		if (!this->FindAndPopulateRelay(2)) return false; // EXIT

		if (DEBUG) this->exitNode->PrintRelayInfo();

		if (DEBUG) printf("[DEBUG] Guard node ready, start sending VERSION to guard.\n");

		// All nodes found! Free some RAM
		this->relaySearcher.reset();

		// Now start to build the path

		// Build the client and connect to guard
		
		this->sClient = make_unique<BriandIDFSocketTlsClient>();
		this->sClient->SetVerbose(DEBUG);
		this->sClient->SetID(9999);
		this->sClient->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		// TODO : find a way to validate requests.
		// Not providing a CACert will be a leak of security but hard-coding has disadvantages...

		//this->sClient->setInsecure();

		// Connect to GUARD

		if ( ! this->sClient->Connect(this->guardNode->GetHost().c_str(), this->guardNode->GetPort() ) ) {
			if (VERBOSE) printf("[ERR] Failed to connect to Guard.\n");
			this->Cleanup();
			return false;
		}

		if (DEBUG) printf("[DEBUG] Connected to guard node.\n");

		/** Steps validation */
		bool stepDone = false;

		// Here I will use the IN-PROTOCOL HANDSHAKE
		stepDone = this->StartInProtocolWithGuard(false); // false = do not answer with self authenticate

		if (!stepDone) {
			if (DEBUG) printf("[DEBUG] Failed to conclude InProtocol with guard.\n");
			return false;
		}

		// If the relay do not have an Ed25519 identity, the CREATE2 will fail.
		// This version does not support old CREATE.

		if (this->guardNode->certRSAEd25519CrossCertificate == nullptr) {
			if (DEBUG) printf("[DEBUG] The guard is missing the Ed25519 identity certificate so a CREATE2 is impossible.\n");
			return false;
		}


		if (DEBUG) printf("[DEBUG] All information complete. Starting creating the circuit with CREATE2.\n");

		// Re-setup CircID with 4 bytes (link protocol >=4)

		// TODO / do not understand:
		// To prevent CircID collisions, when one node sends a CREATE/CREATE2
		// cell to another, it chooses from only one half of the possible
		// values based on the ORs' public identity keys.

		this->CIRCID = 0x00000000;
		this->CIRCID += ( Briand::BriandUtils::GetRandomByte() << 24 );
		this->CIRCID += ( Briand::BriandUtils::GetRandomByte() << 16 );
		this->CIRCID += ( Briand::BriandUtils::GetRandomByte() << 8 );
		this->CIRCID += Briand::BriandUtils::GetRandomByte();

		// However looking at tor sources this seems much more important:

		/*
			In link protocol version 4 or higher, whichever node initiated the
   			connection sets its MSB to 1, and whichever node didn't initiate the
   			connection sets its MSB to 0
		*/

		// So it's clear, my circid must have MSB to 1
		this->CIRCID = this->CIRCID | 0x80000000;

		if (DEBUG) printf("[DEBUG] NEW CircID: 0x%08X \n", this->CIRCID);

		// CREATE/CREATE2

		stepDone = this->Create2();

		if (!stepDone) {
			if (DEBUG) printf("[DEBUG] Failed to conclude CREATE2 with guard.\n");
			return false;
		}

		this->isCreating = true;

		if (DEBUG) printf("[DEBUG] CREATE2 success. Extending to Middle node.\n");

		// EXTEND2 to middle

		stepDone = this->Extend2(false);

		if (!stepDone) {
			if (DEBUG) printf("[DEBUG] Failed to conclude EXTEND2 with middle node.\n");
			this->isCreating = false;
			this->TearDown();
			return false;
		}

		if (DEBUG) printf("[DEBUG] EXTEND2 with Middle success. Extending to Exit node.\n");

		// EXTEND2 to exit

		stepDone = this->Extend2(true);

		if (!stepDone) {
			if (DEBUG) printf("[DEBUG] Failed to conclude EXTEND2 with exit node.\n");
			this->isCreating = false;
			this->TearDown();
			return false;
		}

		if (DEBUG) printf("[DEBUG] EXTEND2 with Exit success. All done!!\n");

		if (DEBUG) this->PrintCircuitInfo();

		// Circuit is now OK!

		this->isBuilt = true;
		this->isClean = true;

		this->isCreating = false;
		this->isClosed = false;
		this->isClosing = false;
		
		this->createdOn = BriandUtils::GetUnixTime();

		if (DEBUG) this->PrintCircuitInfo();
		
		return true;
	}

	


	// Stream functions
	// MUST check if built / closed / closing ....
	



	void BriandTorCircuit::TearDown(BriandTorDestroyReason reason /*  = BriandTorDestroyReason::NONE */) {
		this->isClosing = true;

		/*
			To tear down a circuit completely, an OR or OP sends a DESTROY
			cell to the adjacent nodes on that circuit, using the appropriate
			direction's circID.

			The payload of a DESTROY cell contains a single octet, describing the
			reason that the circuit was closed. Similarly, the data of a
			RELAY_TRUNCATED cell also contains this single octet "reason" field. When
			sending a TRUNCATED or DESTROY cell because of another TRUNCATED or
			DESTROY cell, the error code should be propagated. The origin of a circuit always 
			sets this error code to 0, to avoid leaking its version

			The error codes are:

				0 -- NONE            (No reason given.)
				1 -- PROTOCOL        (Tor protocol violation.)
				2 -- INTERNAL        (Internal error.)
				3 -- REQUESTED       (A client sent a TRUNCATE command.)
				4 -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
				5 -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
				6 -- CONNECTFAILED   (Unable to reach relay.)
				7 -- OR_IDENTITY     (Connected to relay, but its OR identity was not
									as expected.)
				8 -- CHANNEL_CLOSED  (The OR connection that was carrying this circuit
									died.)
				9 -- FINISHED        (The circuit has expired for being dirty or old.)
				10 -- TIMEOUT         (Circuit construction took too long)
				11 -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
				12 -- NOSUCHSERVICE   (Request for unknown hidden service)
		*/

		if (this->sClient != nullptr && this->sClient->IsConnected() && (this->isBuilt || this->isCreating) && !this->isClosed) {
			if (DEBUG) printf("[DEBUG] Sending DESTROY cell to Guard with reason %u\n", static_cast<unsigned char>(reason));

			auto tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::DESTROY);

			tempCell->AppendToPayload(static_cast<unsigned char>(reason));
			tempCell->SendCell(this->sClient, true, false);

			if (DEBUG) printf("[DEBUG] DESTROY cell sent.\n");
						
			this->sClient->Disconnect();
			this->sClient.reset();

			if (DEBUG) printf("[DEBUG] Circuit TearDown success.\n");
		}
		else {
			if (DEBUG) printf("[DEBUG] Circuit does not need TearDown.\n");
		}

		// However, always reset values to avoid misunderstandings
		// after calling this function
		this->isClosing = false;
		this->isCreating = false;
		this->isClean = false;
		this->isBuilt = false;
		this->isClosed = true;
	}

	void BriandTorCircuit::PrintCircuitInfo() {
		if (VERBOSE) {
			if (this->isBuilt && !(this->isClosing || this->isClosed)) {
				printf("[INFO] Circuit with ID %08X is operative since Unix time %lu.\n", this->CIRCID, this->createdOn);
				printf("[INFO] You <----> G[%s] <----> M[%s] <----> E[%s] <----> Web\n", this->guardNode->nickname->c_str(), this->middleNode->nickname->c_str(), this->exitNode->nickname->c_str());
			}
			else {
				printf("[INFO] Circuit is not built, closed or in closing.\n");
			}
		}
	}

}