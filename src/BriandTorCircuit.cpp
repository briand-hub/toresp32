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

using namespace std;

namespace Briand {

	BriandTorCircuit::BriandTorCircuit() {
		this->guardNode = nullptr;
		this->middleNode = nullptr;
		this->exitNode = nullptr;
		this->relaySearcher = nullptr;

		this->createdOn = 0;

		this->CIRCID = 0;
		this->LINKPROTOCOLVERSION = 0;
		this->CURRENT_STREAM_ID = 0;
		this->CURRENT_STREAM_WINDOW = 1000;
		this->RSD = nullptr;

		this->internalID = -1;
		this->paddingSent = 0;
		this->paddingSentOn = 0;

		this->sClient = nullptr;
		this->CIRCUIT_STATUS = CircuitStatusFlag::NONE;
	}

	void BriandTorCircuit::StatusSetFlag(const CircuitStatusFlag& flag) {
		// If ANY flag is set, this circuit must be considered DIRT
		if (flag > 0 && !this->StatusGetFlag(CircuitStatusFlag::DIRT)) {
			this->CIRCUIT_STATUS = this->CIRCUIT_STATUS | CircuitStatusFlag::DIRT;
		}

		this->CIRCUIT_STATUS = this->CIRCUIT_STATUS | flag;
	}

	void BriandTorCircuit::StatusUnsetFlag(const CircuitStatusFlag& flag) {
		this->CIRCUIT_STATUS = this->CIRCUIT_STATUS & (~flag);
	}

	void BriandTorCircuit::StatusResetTo(const CircuitStatusFlag& flag) {
		// If it was dirt, remember it.
		bool wasDirt = this->StatusGetFlag(CircuitStatusFlag::DIRT);

		this->CIRCUIT_STATUS = CircuitStatusFlag::NONE;
		this->StatusSetFlag(flag);

		// If it was dirt, remember it.
		if (wasDirt) this->StatusSetFlag(CircuitStatusFlag::DIRT);
	}

	bool BriandTorCircuit::StatusGetFlag(const CircuitStatusFlag& flag) {
		return (this->CIRCUIT_STATUS & flag) > 0;
	}

	string BriandTorCircuit::StatusGetString() {
		ostringstream ss;
		
		if (this->CIRCUIT_STATUS == CircuitStatusFlag::NONE) {
			ss << "NONE";
		} 
		if (this->StatusGetFlag(CircuitStatusFlag::BUILDING)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "BUILDING";
		} 
		if (this->StatusGetFlag(CircuitStatusFlag::BUILT)) {
			if (ss.str().size() > 0) ss << ","; 
			ss << "BUILT";
		}
		if (this->StatusGetFlag(CircuitStatusFlag::BUSY)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "BUSY";
		}
		if (this->StatusGetFlag(CircuitStatusFlag::CLEAN)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "CLEAN";
		}
		if (this->StatusGetFlag(CircuitStatusFlag::CLOSED)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "CLOSED";
		}
		if (this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "STREAM_READY";
		}
		if (this->StatusGetFlag(CircuitStatusFlag::STREAMING)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "STREAMING";
		}
		if (this->StatusGetFlag(CircuitStatusFlag::DIRT)) {
			if (ss.str().size() > 0) ss << ",";
			ss << "DIRT";
		}

		return ss.str();
	}

	bool BriandTorCircuit::IsInstanceBusy() {
		return this->StatusGetFlag(CircuitStatusFlag::BUSY);
	}

	BriandTorCircuit::~BriandTorCircuit() {
		// Wait for any instance work to be finished
		while ( this->StatusGetFlag(CircuitStatusFlag::BUSY) );

		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		// If it was previously created or a tentative was in place, tear down the previous.
		if ( this->StatusGetFlag(CircuitStatusFlag::BUILT) || this->StatusGetFlag(CircuitStatusFlag::BUILDING) ) {
			this->TearDown();
		}

		if (!this->StatusGetFlag(CircuitStatusFlag::CLOSED)) {
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

		if (this->RSD != nullptr) {
			mbedtls_md_free(this->RSD.get());
			this->RSD.reset();
		}

		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
	}

	void BriandTorCircuit::Cleanup() {

		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		if (this->relaySearcher != nullptr) this->relaySearcher.reset();
		if (this->sClient != nullptr) {
			// close connetion if active
			if (this->sClient->IsConnected())
				this->sClient->Disconnect();
			this->sClient.reset();
		}
		
		this->CURRENT_STREAM_ID = 0;

		this->StatusResetTo(CircuitStatusFlag::CLOSED);
	}

	bool BriandTorCircuit::FindAndPopulateRelay(const unsigned char& relayType) {
		string relayS;

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			
			switch (relayType) {
				case 0: relayS = "guard"; break;
				case 1: relayS = "middle"; break;
				case 2: relayS = "exit"; break;
				default: relayS = to_string(relayType) + "(?)";
			}
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Starting search for %s node.\n", relayS.c_str());

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

			ESP_LOGD(LOGTAG, "[DEBUG] Retrieving descriptors for %s node...\n", relayS.c_str());

			if (tentative->FetchDescriptorsFromAuthority()) {

				if (relayType == 0) this->guardNode = std::move(tentative);
				else if (relayType == 1) this->middleNode = std::move(tentative);
				else if (relayType == 2) this->exitNode = std::move(tentative);

				done = true;
				ESP_LOGD(LOGTAG, "[DEBUG] %s node ok.\n", relayS.c_str());
			}
			else {
				ESP_LOGD(LOGTAG, "[DEBUG] Retrieving descriptors for %s node FAILED\n", relayS.c_str());
			}
		}

		if (!done) ESP_LOGW(LOGTAG, "[ERR] FAIL to get a valid %s node.\n", relayS.c_str());

		return done;
	}

	bool BriandTorCircuit::StartInProtocolWithGuard(bool authenticateSelf /* = false*/) {
		// Choose a first, random CircID (does not matter here, see CREATE2)
		// The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have CIRCID_LEN == 2 for backward compatibility.

		this->CIRCID = ( Briand::BriandUtils::GetRandomByte() << 8 ) + Briand::BriandUtils::GetRandomByte();

		if(esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) printf("[DEBUG] Temporary CircID = 0x%04X\n", this->CIRCID);

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

		ESP_LOGD(LOGTAG, "[DEBUG] Sending first VERSION to guard.\n");

		tempCell = make_unique<Briand::BriandTorCell>(0, this->CIRCID, Briand::BriandTorCellCommand::VERSIONS);

		// link version 4 at least please!!!
		tempCell->AppendTwoBytesToPayload(0x0004);
		tempCell->AppendTwoBytesToPayload(0x0005);

		tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell.reset();

		if (tempCellResponse->size() == 0) {
			ESP_LOGW(LOGTAG, "[ERR] Error on sending first VERSION to Guard.\n");
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Cell response! :-D Contents (first 32 bytes): ");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );
		
		// The response contents should have a lot of informations.

		// First is a version cell containing valid linkprotocols to use.
		// The cell is always backward-compatible

		// start an empty cell to build with buffer

		tempCell =  make_unique<Briand::BriandTorCell>(0, 0, Briand::BriandTorCellCommand::PADDING); 
		tempCell->BuildFromBuffer(tempCellResponse, 2); // Link protocol is always 2 for VERSION
		this->LINKPROTOCOLVERSION = tempCell->GetLinkProtocolFromVersionCell();

		if (this->LINKPROTOCOLVERSION == 0) {
			ESP_LOGW(LOGTAG, "[ERR] Error on receiving first VERSION from Guard, unable to negotiate link protocol version.\n");
			this->Cleanup();
			return false;
		}
		else if (this->LINKPROTOCOLVERSION < 4) {
			ESP_LOGW(LOGTAG, "[ERR] Guard has an old link protocol (version %d but required >= 4).\n", this->LINKPROTOCOLVERSION);
			this->Cleanup();
			return false;
		}
		else if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Link protocol version %d negotiation SUCCESS.\n", this->LINKPROTOCOLVERSION);
		}

		// The next part of buffer should be a CERTS cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		ESP_LOGD(LOGTAG, "[DEBUG] Next chunk (first 32 bytes printed): ");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::CERTS) {
			ESP_LOGW(LOGTAG, "[ERR] Error, expected CERTS cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Got CERTS cell!\n");
		
		if (! tempCell->SetRelayCertificatesFromCertsCell(this->guardNode) ) {
			ESP_LOGW(LOGTAG, "[ERR] CERTS cell seems not valid.\n");
			this->Cleanup();
			return false;
		}

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Guard has %d certifcates loaded.\n", this->guardNode->GetCertificateCount());
			this->guardNode->PrintAllCertificateShortInfo();
		} 

		if ( ! this->guardNode->ValidateCertificates() ) {
			ESP_LOGW(LOGTAG, "[ERR] CERTS cell received has invalid certificates.\n");
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] CERTS cell certificates validation succeded.\n");

		// The next part of buffer should be a AUTH_CHALLENGE cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		// AUTH_CHALLENGE is used for authenticate, might not do that.

		ESP_LOGD(LOGTAG, "[DEBUG] Next chunk (first 32 bytes printed): ");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::AUTH_CHALLENGE) {
			ESP_LOGW(LOGTAG, "[ERR] Error, expected AUTH_CHALLENGE cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Got AUTH_CHALLENGE cell!\n");

		ESP_LOGD(LOGTAG, "[DEBUG] WARNING: AUTH_CHALLENGE cell is not handled at moment from this version.\n");
		// TODO dont't mind for now..

		// The next part of buffer should be a NETINFO cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::NETINFO) {
			ESP_LOGW(LOGTAG, "[ERR] Error, expected NETINFO cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Got NETINFO cell!\n");

		ESP_LOGD(LOGTAG, "[DEBUG] Info: this version do not check or handle incoming NETINFO cell.\n");
		// TODO dont't mind for now..

		ESP_LOGD(LOGTAG, "[DEBUG] Got all cells needed for handshake :-)\n");

		// The next part of buffer needs to be ignored, could be cleared and save RAM.
		// WARNING: for answer to auth all bytes received must be kept!
		tempCellResponse.reset();
		tempCell.reset();

		// After authentication....

		//
		// TODO ?
		// 

		// Answer with NETINFO CELL

		ESP_LOGD(LOGTAG, "[DEBUG] Sending NETINFO cell to guard.\n");

		tempCell = make_unique<BriandTorCell>( this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::NETINFO );
		struct in_addr public_ip;
		inet_aton(BriandUtils::GetPublicIPFromIPFY().c_str(), &public_ip);
		tempCell->BuildAsNETINFO( public_ip );

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] NETINFO cell payload to send: ");
			tempCell->PrintCellPayloadToSerial();
		} 

		tempCellResponse = tempCell->SendCell(this->sClient, false, false); // Last false: do not expect a response

		ESP_LOGD(LOGTAG, "[DEBUG] NETINFO cell sent.\n");

		// Freee
		tempCell.reset();
		tempCellResponse.reset();
		
		return true;
	}

	bool BriandTorCircuit::Create2() {
		ESP_LOGD(LOGTAG, "[DEBUG] Sending CREATE2 cell to guard.\n");

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
			ESP_LOGD(LOGTAG, "[DEBUG] Failed on building cell CREATE2.\n");
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 sent. Waiting for CREATED2.\n");
		auto tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);
		
		if (!tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION)) {
			ESP_LOGW(LOGTAG, "[ERR] Error, response cell had invalid bytes (failed to build from buffer).\n");
			this->Cleanup();
			return false;
		}
		
		// If a DESTROY given, tell me why
		if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
			ESP_LOGW(LOGTAG, "[ERR] Error, DESTROY received! Reason = 0x%02X\n", tempCell->GetPayload()->at(0));
			this->Cleanup();
			return false;
		}

		if (tempCell->GetCommand() != BriandTorCellCommand::CREATED2) {
			ESP_LOGW(LOGTAG, "[ERR] Error, response contains %s cell instead of CREATED2. Failure.\n", BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Got CREATED2, payload:");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();

		// Finish the handshake!
		if (!this->guardNode->FinishHandshake(tempCell->GetPayload())) {
			ESP_LOGW(LOGTAG, "[ERR] Error on concluding handshake!\n");
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
		ESP_LOGD(LOGTAG, "[DEBUG] Sending EXTEND2 cell to guard.\n");

		// EXTEND2 is a RELAY cell! (RELAY_EARLY since link protocol v2)

		auto tempCell = make_unique<Briand::BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::RELAY_EARLY);
		
		if (exitNode) {
			if (!tempCell->BuildAsEXTEND2(*this->exitNode.get())) {
				ESP_LOGD(LOGTAG, "[DEBUG] Failed on building cell EXTEND2 to exit.\n");
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}
		else {
			if (!tempCell->BuildAsEXTEND2(*this->middleNode.get())) {
				ESP_LOGD(LOGTAG, "[DEBUG] Failed on building cell EXTEND2 to middle.\n");
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}

		// Prepare a StreamID of all zeros (relay commands with [control] use all-zero streamid!)
		unsigned short streamID = 0x0000;

		ESP_LOGD(LOGTAG, "[DEBUG] StreamID is: %04X\n", streamID);

		// After building the main contents, prepare it as a relay cell
		if (exitNode) {
			tempCell->PrepareAsRelayCell(BriandTorCellRelayCommand::RELAY_EXTEND2, streamID, this->middleNode->KEY_ForwardDigest_Df);
		}
		else {
			tempCell->PrepareAsRelayCell(BriandTorCellRelayCommand::RELAY_EXTEND2, streamID, this->guardNode->KEY_ForwardDigest_Df);
		}

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] EXTEND2 contents before encryption: ");
			tempCell->PrintCellPayloadToSerial();
		}

		// Then encrypt
		if (exitNode) {
			// Encrypt with middle key
			tempCell->ApplyOnionSkin(*this->middleNode);
			ESP_LOGD(LOGTAG, "[DEBUG] Applied MIDDLE onion skin, encrypted contents: ");
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
			// Encrypt with guard keyù
			tempCell->ApplyOnionSkin(*this->guardNode);
			ESP_LOGD(LOGTAG, "[DEBUG] Applied GUARD onion skin, encrypted contents: ");
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
		}
		else {
			// Encrypt with guard key
			tempCell->ApplyOnionSkin(*this->guardNode);
			ESP_LOGD(LOGTAG, "[DEBUG] Applied GUARD onion skin, encrypted contents: ");
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
		}

		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 is going to be sent. Waiting for EXTENDED2.\n");
		auto tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);
		
		// Build the basic cell

		if (!tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION)) {
			ESP_LOGW(LOGTAG, "[ERR] Error, response cell had invalid bytes (failed to build from buffer).\n");
			this->TearDown();
			this->Cleanup();
			return false;
		}
		
		// If a DESTROY given, tell me why
		if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
			ESP_LOGW(LOGTAG, "[ERR] Error, DESTROY received! Reason = 0x%02X\n", tempCell->GetPayload()->at(0));
			this->TearDown();
			this->Cleanup();
			return false;
		}

		if (tempCell->GetCommand() != BriandTorCellCommand::RELAY) {
			ESP_LOGW(LOGTAG, "[ERR] Error, response contains %s cell instead of RELAY. Failure.\n", BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->TearDown();
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Got RELAY cell, payload:");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();

		// Decrypt payload of received cell
		if (exitNode) {
			tempCell->PeelOnionSkin(*this->guardNode);

			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Removed GUARD onion skin with Kb key: ");
				BriandUtils::PrintByteBuffer(*this->guardNode->KEY_Backward_Kb.get());
				printf("[DEBUG] RELAY cell payload after decryption: ");
				tempCell->PrintCellPayloadToSerial();
			} 

			// Check if the cell is recognized

			if (tempCell->IsRelayCellRecognized(0x0000, this->guardNode->KEY_BackwardDigest_Db)) {
				// Have been recognized, if this is true here, an error occoured...
				tempCell->BuildRelayCellFromPayload(this->guardNode->KEY_BackwardDigest_Db);
				BriandTorCellRelayCommand unexpectedCmd = tempCell->GetRelayCommand();
				if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG] RELAY recognized at Guard, something wrong, cell relay command is: %s. Payload: ", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
					tempCell->PrintCellPayloadToSerial();
				}

				ESP_LOGW(LOGTAG, "[ERR] Error on extending to exit node, received unexpected cell %s\n", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
				this->TearDown();
				this->Cleanup();
				return false;
			}

			// If not, then peel out the middle node skin

			tempCell->PeelOnionSkin(*this->middleNode);

			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Removed MIDDLE onion skin with Kb key: ");
				BriandUtils::PrintByteBuffer(*this->middleNode->KEY_Backward_Kb.get());
				printf("[DEBUG] RELAY cell payload after decryption: ");
				tempCell->PrintCellPayloadToSerial();
			} 

			// Check if cell is recognized 

			if (!tempCell->IsRelayCellRecognized(0x0000, this->middleNode->KEY_BackwardDigest_Db)) {
				ESP_LOGD(LOGTAG, "[DEBUG] Cell has not been recognized, failure.\n");
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}
		else {
			tempCell->PeelOnionSkin(*this->guardNode);

			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Removed GUARD onion skin with Kb key: ");
				BriandUtils::PrintByteBuffer(*this->guardNode->KEY_Backward_Kb.get());
				printf("[DEBUG] RELAY cell payload after decryption: ");
				tempCell->PrintCellPayloadToSerial();
			} 

			// Check if cell is recognized 

			if (!tempCell->IsRelayCellRecognized(0x0000, this->guardNode->KEY_BackwardDigest_Db)) {
				ESP_LOGD(LOGTAG, "[DEBUG] Cell has not been recognized, failure.\n");
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}

		// Verification passed, now build cell informations 
		if (exitNode && !tempCell->BuildRelayCellFromPayload(this->middleNode->KEY_BackwardDigest_Db)) {
			ESP_LOGW(LOGTAG, "[ERR] Error on rebuilding RELAY cell informations from exit node, invalid cell.\n");
			this->TearDown();
			this->Cleanup();
			return false;
		}
		if (!exitNode && !tempCell->BuildRelayCellFromPayload(this->guardNode->KEY_BackwardDigest_Db)) {
			ESP_LOGW(LOGTAG, "[ERR] Error on rebuilding RELAY cell informations from middle node, invalid cell.\n");
			this->TearDown();
			this->Cleanup();
			return false;
		}

		if (tempCell->GetRelayCommand() != BriandTorCellRelayCommand::RELAY_EXTENDED2) {
			ESP_LOGD(LOGTAG, "[DEBUG] Expected EXTENDED2 but received %s\n", BriandUtils::BriandTorRelayCellCommandToString(tempCell->GetRelayCommand()).c_str());
			this->TearDown();
			this->Cleanup();
			return false;
		}

		// Finish the handshake!

		/* The payload of an EXTENDED2 cell is the same as the payload of a CREATED2 cell */
		if (exitNode) {
			if (!this->exitNode->FinishHandshake(tempCell->GetPayload())) {
				ESP_LOGW(LOGTAG, "[ERR] Error on concluding EXTENDED2 handshake with exit!\n");
				// Always destroy if fails
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}
		else {
			if (!this->middleNode->FinishHandshake(tempCell->GetPayload())) {
				ESP_LOGW(LOGTAG, "[ERR] Error on concluding EXTENDED2 handshake with middle!\n");
				// Always destroy if fails
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}

		ESP_LOGD(LOGTAG, "[DEBUG] EXTENDED2 Success, circuit has now a new hop\n");

		// Free buffers
		tempCell.reset();
		tempCellResponse.reset();

		return true;
	}

	bool BriandTorCircuit::BuildCircuit(bool forceTorCacheRefresh /* = false*/) {
		// If it was previously created or a tentative was in place, tear down the previous.
		if ( (this->StatusGetFlag(CircuitStatusFlag::BUILT) || this->StatusGetFlag(CircuitStatusFlag::BUILDING)) && !this->StatusGetFlag(CircuitStatusFlag::CLOSING) ) {
			this->TearDown();
		}

		// Set circuit busy (long work!)
		this->StatusResetTo(CircuitStatusFlag::BUSY);
		
		// Prepare for search
		this->relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();

		if (forceTorCacheRefresh) {
			relaySearcher->InvalidateCache(true); // invalidate and rebuild the cache
		}

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

		ESP_LOGD(LOGTAG, "[DEBUG] Starting relay search.\n");

		// GUARD
		if (!this->FindAndPopulateRelay(0)) { 
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;  
		}

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->guardNode->PrintRelayInfo();

		ESP_LOGD(LOGTAG, "[DEBUG] Starting relay search for middle node.\n");
		
		// MIDDLE
		if (!this->FindAndPopulateRelay(1)) { 
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;  
		} 

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->middleNode->PrintRelayInfo();
		
		ESP_LOGD(LOGTAG, "[DEBUG] Starting relay search for exit node.\n");

		// EXIT
		if (!this->FindAndPopulateRelay(2)) { 
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;  
		} 

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->exitNode->PrintRelayInfo();

		ESP_LOGD(LOGTAG, "[DEBUG] Guard node ready, start sending VERSION to guard.\n");

		// All nodes found! Free some RAM
		this->relaySearcher.reset();

		// The creation starts now
		this->StatusSetFlag(CircuitStatusFlag::BUILDING);

		// Now start to build the path

		// Build the client and connect to guard
		
		this->sClient = make_unique<BriandIDFSocketTlsClient>();
		this->sClient->SetVerbose(false);
		this->sClient->SetID(this->internalID);
		this->sClient->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);

		// Connect to GUARD

		if ( ! this->sClient->Connect(this->guardNode->GetHost().c_str(), this->guardNode->GetPort() ) ) {
			ESP_LOGW(LOGTAG, "[ERR] Failed to connect to Guard.\n");
			this->Cleanup();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Connected to guard node.\n");

		/** Steps validation */
		bool stepDone = false;

		// Here I will use the IN-PROTOCOL HANDSHAKE
		stepDone = this->StartInProtocolWithGuard(false); // false = do not answer with self authenticate

		if (!stepDone) {
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude InProtocol with guard.\n");
			this->Cleanup();
			return false;
		}

		// If the relay do not have an Ed25519 identity, the CREATE2 will fail.
		// This version does not support old CREATE.

		if (this->guardNode->certRSAEd25519CrossCertificate == nullptr) {
			ESP_LOGD(LOGTAG, "[DEBUG] The guard is missing the Ed25519 identity certificate so a CREATE2 is impossible.\n");
			this->Cleanup();
			return false;
		}


		ESP_LOGD(LOGTAG, "[DEBUG] All information complete. Starting creating the circuit with CREATE2.\n");

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

		ESP_LOGD(LOGTAG, "[DEBUG] NEW CircID: 0x%08X \n", this->CIRCID);

		// CREATE/CREATE2

		stepDone = this->Create2();

		if (!stepDone) {
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude CREATE2 with guard.\n");
			this->TearDown();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 success. Extending to Middle node.\n");

		// EXTEND2 to middle

		stepDone = this->Extend2(false);

		if (!stepDone) {
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude EXTEND2 with middle node.\n");
			this->TearDown();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 with Middle success. Extending to Exit node.\n");

		// EXTEND2 to exit

		stepDone = this->Extend2(true);

		if (!stepDone) {
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude EXTEND2 with exit node.\n");
			this->TearDown();
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 with Exit success. All done!!\n");

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->PrintCircuitInfo();

		// Circuit is now OK!

		this->StatusResetTo(CircuitStatusFlag::BUILT);
		this->StatusSetFlag(CircuitStatusFlag::STREAM_READY);
		this->StatusSetFlag(CircuitStatusFlag::CLEAN);
		
		this->createdOn = BriandUtils::GetUnixTime();

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->PrintCircuitInfo();
		
		return true;
	}

	bool BriandTorCircuit::TorStreamWriteData(const BriandTorCellRelayCommand& command, const unique_ptr<vector<unsigned char>>& data) {
		// Circuit must be ready to stream
		this->StatusUnsetFlag(CircuitStatusFlag::CLEAN);

		if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamWriteData called but circuit is not built and ready to stream.\n");
			return false;
		}

		if (data == nullptr) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamWriteData called with NULL request payload.\n");
			return false;
		}

		// prepare the basic cell
		auto tempCell = make_unique<Briand::BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::RELAY);

		// Add the payload and prepare the cell
		if (!tempCell->AppendBytesToPayload(*data.get())) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamWriteData called with too large payload.\n");
			return false;
		}

		tempCell->PrepareAsRelayCell(command, this->CURRENT_STREAM_ID, this->exitNode->KEY_ForwardDigest_Df);

		// Encrypt with exit key
		tempCell->ApplyOnionSkin(*this->exitNode);
		// Encrypt with middle key
		tempCell->ApplyOnionSkin(*this->middleNode);
		// Encrypt with guard key
		tempCell->ApplyOnionSkin(*this->guardNode);

		// Send cell but and do not wait any answer.
		tempCell->SendCell(this->sClient, false, false);

		return true;
	}

	unique_ptr<BriandTorCell> BriandTorCircuit::TorStreamReadData() {
		// Circuit must be ready to stream
		this->StatusUnsetFlag(CircuitStatusFlag::CLEAN);

		if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamReadData called but circuit is not built and ready to stream.\n");
			return nullptr;
		}

		// Read the socket, as all RELAY/DESTROY/PADDING cells are fixed-length cells, this is easy...
		this->sClient->SetReceivingBufferSize(514); 
		auto tempData = this->sClient->ReadData(true);
		ESP_LOGD(LOGTAG, "[DEBUG] TorStreamReadData %d bytes read.\n", tempData->size());

		// Build the basic cell from received data
		auto tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);

		if (!tempCell->BuildFromBuffer(tempData, this->LINKPROTOCOLVERSION)) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamReadData error, response cell had invalid bytes (failed to build from buffer).\n");
			return nullptr;
		}

		// If cell does not belong to this circuit, ignore it.
		if (tempCell->GetCircID() != this->CIRCID) {
			ESP_LOGD(LOGTAG, "[DEBUG] TorStreamReadData received a cell with a different CircID (this is %08X, received %08X), ignoring.\n", this->CIRCID, tempCell->GetCircID());
			return std::move(tempCell);
		}

		// If a DESTROY given must tear down, tell me why
		if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamReadData error, DESTROY received! Reason = 0x%02X\n", tempCell->GetPayload()->at(0));
			this->TearDown();
			this->Cleanup();
			return std::move(tempCell);
		}

		// If it is a RELAY cell, must be decrypted.
		if (tempCell->GetCommand() == BriandTorCellCommand::RELAY) {
			// Cell recognization 

			// Peel out the guard skin
			tempCell->PeelOnionSkin(*this->guardNode.get());
			
			if (tempCell->IsRelayCellRecognized(this->CURRENT_STREAM_ID, this->guardNode->KEY_BackwardDigest_Db)) {
				// If is recognized here, an error occoured.
				tempCell->BuildRelayCellFromPayload(this->guardNode->KEY_BackwardDigest_Db);
				BriandTorCellRelayCommand unexpectedCmd = tempCell->GetRelayCommand();
				if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG] TorStreamReadData RELAY recognized at Guard, something wrong, cell relay command is: %s. Payload: ", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
					tempCell->PrintCellPayloadToSerial();
				}

				ESP_LOGW(LOGTAG, "[ERR] TorStreamReadData error, received unexpected cell from guard node: %s\n", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());

				return std::move(tempCell);
			}

			// Peel out the middle skin
			tempCell->PeelOnionSkin(*this->middleNode.get());
			
			if (tempCell->IsRelayCellRecognized(this->CURRENT_STREAM_ID, this->middleNode->KEY_BackwardDigest_Db)) {
				// If is recognized here, an error occoured.
				tempCell->BuildRelayCellFromPayload(this->middleNode->KEY_BackwardDigest_Db);
				BriandTorCellRelayCommand unexpectedCmd = tempCell->GetRelayCommand();
				if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG] TorStreamReadData RELAY recognized at Middle, something wrong, cell relay command is: %s. Payload: ", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
					tempCell->PrintCellPayloadToSerial();
				}

				ESP_LOGW(LOGTAG, "[ERR] TorStream error, received unexpected cell from middle node: %s\n", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());

				return std::move(tempCell);					
			}

			// Peel out the exit skin, now the cell MUST be recognized...
			tempCell->PeelOnionSkin(*this->exitNode.get());

			if (!tempCell->IsRelayCellRecognized(this->CURRENT_STREAM_ID, this->exitNode->KEY_BackwardDigest_Db)) {
				// If is NOT recognized here, an error occoured.
				if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG] TorStreamReadData RELAY NOT recognized at Exit, something wrong. Raw payload: ");
					tempCell->PrintCellPayloadToSerial();
				}

				ESP_LOGW(LOGTAG, "[ERR] TorStream error, unrecognized cell from exit node.\n");

				return nullptr;
			}

			// Here cell is recognized

			// If this is a RELAY_DATA remember to update the window and the rolling digest!
			if (tempCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_DATA) {
				// Update current window
				this->CURRENT_STREAM_WINDOW--;

				// Start the digest if not done before
				if (this->RSD == nullptr) {
					this->RSD = make_unique<mbedtls_md_context_t>();
					mbedtls_md_init(this->RSD.get());
					mbedtls_md_setup(this->RSD.get(), mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
					mbedtls_md_starts(this->RSD.get());
					ESP_LOGD(LOGTAG, "[DEBUG] Circuit Stream Rolling Digest started.\n");
				}

				// Update the digest
				mbedtls_md_update(this->RSD.get(), tempCell->GetPayload()->data(), tempCell->GetPayload()->size());
				
				ESP_LOGD(LOGTAG, "[DEBUG] Circuit Stream Rolling Digest updated.\n");

				// Check if a new RELAY_SENDME is required
				if (this->CURRENT_STREAM_WINDOW <= 990) {
					ESP_LOGD(LOGTAG, "[DEBUG] A RELAY_SENDME is required.\n");

					/*
						The RELAY_SENDME payload contains the following:

						VERSION     [1 byte]
						DATA_LEN    [2 bytes]
						DATA        [DATA_LEN bytes]
					*/

					auto sendMePayload = make_unique<vector<unsigned char>>();
					sendMePayload->push_back(0x01); // version 1 authenticated cell
					sendMePayload->push_back(static_cast<unsigned char>(this->RSD->md_info->size));

					// Make a copy of the current digest and calculate the digest without updating.
					auto digestCopy = make_unique<mbedtls_md_context_t>();
					auto outBuf = BriandUtils::GetOneOldBuffer(this->RSD->md_info->size);
					mbedtls_md_init(digestCopy.get());
					mbedtls_md_setup(digestCopy.get(), this->RSD->md_info, 0);
					mbedtls_md_clone(digestCopy.get(), this->RSD.get());
					mbedtls_md_finish(digestCopy.get(), outBuf.get());
					mbedtls_md_free(digestCopy.get());
					digestCopy.reset();

					for (unsigned char i = 0; i<this->RSD->md_info->size; i++)
						sendMePayload->push_back(outBuf[i]);

					// Send the cell
					if (!this->TorStreamWriteData(BriandTorCellRelayCommand::RELAY_SENDME, sendMePayload)) {
						ESP_LOGD(LOGTAG, "[DEBUG] RELAY_SENDME cell NOT sent (errors). Circuit will be torn down.\n");
						this->TearDown();
					}
					else {
						ESP_LOGD(LOGTAG, "[DEBUG] RELAY_SENDME sent.\n");
					}

					// Re-increment by 100 the window
					this->CURRENT_STREAM_WINDOW += 100;
				}
			}

			// Build informations (decrypted payload etc.)
			if (!tempCell->BuildRelayCellFromPayload(this->exitNode->KEY_BackwardDigest_Db)) {
				ESP_LOGW(LOGTAG, "[ERR] TorStreamReadData error on rebuilding RELAY cell informations from exit node, invalid response cell.\n");
				return nullptr;
			}
		}

		tempData.reset();
		ESP_LOGD(LOGTAG, "[DEBUG] TorStreamReadData success.\n");

		return std::move(tempCell);
	}

	unique_ptr<vector<unsigned char>> BriandTorCircuit::TorStreamSingle(const BriandTorCellRelayCommand& command, const unique_ptr<vector<unsigned char>>& requestPayload, const BriandTorCellRelayCommand& waitFor) {
		unique_ptr<vector<unsigned char>> response = nullptr;

		// Set circuit busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);
		
		// Write data
		if (!this->TorStreamWriteData(command, requestPayload)) {
			ESP_LOGW(LOGTAG, "[ERR] TorStreamSingle error on writing request.\n");
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return response;
		}

		// Read data until the desidered command is found or an error is thrown.
		do {
			auto readCell = this->TorStreamReadData();

			// If nullptr => error
			if (readCell == nullptr) {
				ESP_LOGW(LOGTAG, "[ERR] TorStreamSingle error on reading response cell.\n");
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return response;
			}

			// If PADDING cell or CIRCID not matching, ignore it.
			if (readCell->GetCircID() != this->CIRCID || readCell->GetCommand() == BriandTorCellCommand::PADDING) {
				ESP_LOGD(LOGTAG, "[DEBUG] TorStreamSingle ignoring cell.\n");
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				continue;
			}

			// Check if the stream id is the right one (otherwise is a protocol violation!)
			if (readCell->GetStreamID() != this->CURRENT_STREAM_ID) {
				ESP_LOGW(LOGTAG, "[WARN] TorStreamRead received a non-matching StreamID (current: %04X received: %04X) Destroy with protocol violation.\n", this->CURRENT_STREAM_ID, readCell->GetStreamID());
				this->TearDown();
				this->Cleanup();
				return response;
			}

			// If DESTROY, return error.
			if (readCell->GetCommand() == BriandTorCellCommand::DESTROY) {
				ESP_LOGW(LOGTAG, "[WARN] TorStreamSingle received circuit DESTROY.\n");
				this->TearDown();
				this->Cleanup();
				return response;
			}

			// If this is a RELAY cell, check for the command.
			// If not, ignore it and continue.
			if (readCell->GetCommand() == BriandTorCellCommand::RELAY) {
				// If RELAY cell but command is TRUNCATE => error
				if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_TRUNCATE || readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_TRUNCATED) 
				{
					ESP_LOGW(LOGTAG, "[WARN] TorStreamSingle received RELAY_TRUNCATE / RELAY_TRUNCATED.\n");
					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					return response;
				}

				// Check if this is the desidered command
				if (readCell->GetRelayCommand() != waitFor) {
					if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
						printf("[ERR] TorStreamSingle failed, received unexpected cell from exit node: %s, payload: ", BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
						readCell->PrintCellPayloadToSerial();
					}

					// If RELAY_END show reason
					if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_END && readCell->GetPayload() != nullptr && readCell->GetPayload()->size() > 0) {
						ESP_LOGW(LOGTAG, "[ERR] TorStreamSingle failed, received unexpected cell from exit node: %s reason: %s.\n", BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str(), BriandUtils::RelayEndReasonToString( static_cast<BriandTorRelayEndReason>(readCell->GetPayload()->at(0)) ).c_str());
					}
					else {
						ESP_LOGW(LOGTAG, "[ERR] TorStreamSingle failed, received unexpected cell from exit node: %s.\n", BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
					}

					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					return response;
				}

				// At this point all is OK

				if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG] TorStreamSingle success, received %s, payload: ", BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
					readCell->PrintCellPayloadToSerial();
				}

				// Take payload and return, that's all!
				response = make_unique<vector<unsigned char>>();
				response->insert(response->begin(), readCell->GetPayload()->begin(), readCell->GetPayload()->end());
			}

		} while (response == nullptr);

		// Unmark busy
		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);

		return response;
	}

	const in_addr BriandTorCircuit::TorResolve(const string& hostname) {
		// Mark busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		in_addr resolved;
		bzero(&resolved, sizeof(resolved));

		// Circuit must be ready to stream
		if (this->StatusGetFlag(CircuitStatusFlag::STREAMING) || !this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			ESP_LOGW(LOGTAG, "[WARN] TorStreamStart error: circuit still streaming or not ready to stream.\n");
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return resolved;
		}

		// Mark streaming
		this->StatusSetFlag(CircuitStatusFlag::STREAMING);

		/*
			To find the address associated with a hostname, the OP sends a
			RELAY_RESOLVE cell containing the hostname to be resolved with a NUL
			terminating byte. (For a reverse lookup, the OP sends a RELAY_RESOLVE
			cell containing an in-addr.arpa address.)
		*/

		ESP_LOGD(LOGTAG, "[DEBUG] Sending RELAY_RESOLVE cell for hostname <%s>.\n", hostname.c_str());

		auto requestPayload = make_unique<vector<unsigned char>>();

		for (const char& c: hostname) {
			requestPayload->push_back(static_cast<unsigned char>(c));
		}
		requestPayload->push_back(0x00); // NUL terminating byte

		// Increment streamid 
		this->CURRENT_STREAM_ID++;

		auto response = this->TorStreamSingle(BriandTorCellRelayCommand::RELAY_RESOLVE, requestPayload, BriandTorCellRelayCommand::RELAY_RESOLVED);
		if (response == nullptr) {
			ESP_LOGW(LOGTAG, "[ERR] TorResolve error, failure on streaming tor request.\n");
			this->StatusUnsetFlag(CircuitStatusFlag::STREAMING);
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return resolved;
		}

		/*
			The OR replies with a RELAY_RESOLVED cell containing any number of answers. Each answer is of the form:

				Type   (1 octet)
				Length (1 octet)
				Value  (variable-width)
				TTL    (4 octets)
			"Length" is the length of the Value field.
			"Type" is one of:

				0x00 -- Hostname
				0x04 -- IPv4 address
				0x06 -- IPv6 address
				0xF0 -- Error, transient
				0xF1 -- Error, nontransient

			IP addresses are given in network order.
        	Hostnames are given in standard DNS order ("www.example.com") and not NUL-terminated.
			The content of Errors is currently ignored.
			For backward compatibility, if there are any IPv4 answers, one of those must be given as the first answer.
		*/

		// Only IPv4 supported at the moment.

		unsigned short i = 0;
		
		while (i < response->size()) {
			unsigned char type = response->at(i);
			if (type == 0xF0 || type == 0xF1) {
				// Error.
				ESP_LOGW(LOGTAG, "[ERR] TorResolve: host could not be resolved, error code = %02X\n", type);
				this->StatusUnsetFlag(CircuitStatusFlag::STREAMING);
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return resolved;
			}
			else if (type != 0x04) {
				i++; // go to the length field
				i += 1 + response->at(i) + 4; // skit TTL and the length, add 1 to point the next information
			}
			else {
				i += 1; // go to the length field
				// resolved octets (WRITE AS C-Style Structure, not Network byte order!)
				resolved.s_addr += response->at(i+1);
				resolved.s_addr += response->at(i+2) << 8;
				resolved.s_addr += response->at(i+3) << 16;
				resolved.s_addr += response->at(i+4) << 24;
				break;
			}
		}

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Found IPv4 address: 0x%08X / %s\n", resolved.s_addr, BriandUtils::IPv4ToString(resolved).c_str());
		}

		this->StatusUnsetFlag(CircuitStatusFlag::STREAMING);
		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);

		return resolved;
	}

	bool BriandTorCircuit::TorStreamStart(const string& hostname, const short& port) {
		// Mark busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		// If circuit is busy or not ready to stream, error
		if (this->StatusGetFlag(CircuitStatusFlag::STREAMING) || !this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			ESP_LOGW(LOGTAG, "[WARN] TorStreamStart error: circuit still streaming or not ready to stream.\n");
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		// Increment streamid 
		this->CURRENT_STREAM_ID++;

		ESP_LOGD(LOGTAG, "[DEBUG] TorStreamStart streamid %hu.\n", this->CURRENT_STREAM_ID);

		/*
			To open a new anonymized TCP connection, the OP chooses an open
			circuit to an exit that may be able to connect to the destination
			address, selects an arbitrary StreamID not yet used on that circuit,
			and constructs a RELAY_BEGIN cell with a payload encoding the address
			and port of the destination host.  The payload format is:

					ADDRPORT [nul-terminated string]
					FLAGS    [4 bytes]

			ADDRPORT is made of ADDRESS | ':' | PORT | [00]

			where  ADDRESS can be a DNS hostname, or an IPv4 address in
			dotted-quad format, or an IPv6 address surrounded by square brackets;
			and where PORT is a decimal integer between 1 and 65535, inclusive.

		*/

		auto payload = make_unique<vector<unsigned char>>();
		for (const char& c : hostname) {
			payload->push_back(static_cast<unsigned char>(c));
		}
		payload->push_back(static_cast<unsigned char>(':'));

		// Also PORT in string format !!!
		for (const char& pc: std::to_string(port)) payload->push_back(static_cast<unsigned char>(pc));

		payload->push_back(0x00);

		/*
			 The FLAGS value has one or more of the following bits set, where
			"bit 1" is the LSB of the 32-bit value, and "bit 32" is the MSB.
			(Remember that all values in Tor are big-endian (see 0.1.1 above), so
			the MSB of a 4-byte value is the MSB of the first byte, and the LSB
			of a 4-byte value is the LSB of its last byte.)

				bit   meaning
				1 -- IPv6 okay.  We support learning about IPv6 addresses and
					connecting to IPv6 addresses.
				2 -- IPv4 not okay.  We don't want to learn about IPv4 addresses
					or connect to them.
				3 -- IPv6 preferred.  If there are both IPv4 and IPv6 addresses,
					we want to connect to the IPv6 one.  (By default, we connect
					to the IPv4 address.)
				4..32 -- Reserved. Current clients MUST NOT set these. Servers
					MUST ignore them.
		
		*/

		payload->push_back(0b00000000); 
		payload->push_back(0b00000000);
		payload->push_back(0b00000000);
		payload->push_back(0b00000000); // IPv4 only

		// Send the request and wait for a RELAY_CONNECTED
		auto response = this->TorStreamSingle(BriandTorCellRelayCommand::RELAY_BEGIN, payload, BriandTorCellRelayCommand::RELAY_CONNECTED);

		if (response == nullptr) {
			ESP_LOGW(LOGTAG, "[WARN] TorStreamStart error: cannot connect to required destination.\n");
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] TorStreamStart success.\n");

		// If success, circuit in streaming!
		this->StatusSetFlag(CircuitStatusFlag::STREAMING);
		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);

		return true;
	}

	bool BriandTorCircuit::TorStreamStart(const in_addr& ipv4, const short& port) {
		// where  ADDRESS can be a DNS hostname, or an IPv4 address in dotted-quad format
		return this->TorStreamStart(BriandUtils::IPv4ToString(ipv4), port);
	}

	void BriandTorCircuit::TorStreamSend(const unique_ptr<vector<unsigned char>>& data, bool& sent) {
		// Mark busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		// Circuit here SHOULD be streaming from a previous TorStreamStart()
		if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY) || !this->StatusGetFlag(CircuitStatusFlag::STREAMING)) {
			ESP_LOGW(LOGTAG, "[WARN] TorStreamStart error: circuit not streaming (missing TorStreamStart()? not built?).\n");
			sent = false;
			return;
		}

		ESP_LOGD(LOGTAG, "[DEBUG] TorStreamSend sending data forward to circuit %08X with StreamID %hu.\n", this->CIRCID, this->CURRENT_STREAM_ID);

		sent = this->TorStreamWriteData(BriandTorCellRelayCommand::RELAY_DATA, data);

		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
	}

	bool BriandTorCircuit::TorStreamRead(unique_ptr<vector<unsigned char>>& buffer, bool& finished, const unsigned short& timeout_s /* = 30*/) {
		// Mark busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		// Get current time
		unsigned long int now = BriandUtils::GetUnixTime();

		finished = false;

		// Buffer must be instanced
		if (buffer == nullptr) {
			ESP_LOGE(LOGTAG, "[ERR] TorStreamRead error: buffer argument is not instanced!\n");
			finished = true;
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		// Circuit here SHOULD be streaming from a previous TorStreamStart()
		if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY) || !this->StatusGetFlag(CircuitStatusFlag::STREAMING)) {
			ESP_LOGW(LOGTAG, "[WARN] TorStreamRead error: circuit not streaming (missing TorStreamStart()? not built?).\n");
			finished = true;
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		// Read until a single significative cell from the stream (a RELAY cell)
		while (1) {
			auto readCell = this->TorStreamReadData();

			// Check timeout
			if (BriandUtils::GetUnixTime() > now+timeout_s) {
				ESP_LOGD(LOGTAG, "[DEBUG] TorStreamRead TIMEOUT (%hu seconds).\n", timeout_s);
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return false;
			}

			// If nullptr => error
			if (readCell == nullptr) {
				ESP_LOGW(LOGTAG, "[ERR] TorStreamRead error on reading response cell.\n");
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return false;
			}

			// If PADDING cell or CIRCID not matching, ignore it.
			if (readCell->GetCircID() != this->CIRCID || readCell->GetCommand() == BriandTorCellCommand::PADDING) {
				ESP_LOGD(LOGTAG, "[DEBUG] TorStreamRead ignoring cell.\n");
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				continue;
			}

			// If DESTROY, return error.
			if (readCell->GetCommand() == BriandTorCellCommand::DESTROY) {
				ESP_LOGW(LOGTAG, "[WARN] TorStreamRead received circuit DESTROY.\n");
				finished = true;
				this->TearDown();
				this->Cleanup();
				return false;
			}

			// If this is a RELAY cell, check for the command.
			// If not, ignore it and continue.
			if (readCell->GetCommand() == BriandTorCellCommand::RELAY) {
				// If RELAY cell but command is TRUNCATE => error
				if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_TRUNCATE || readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_TRUNCATED) 
				{
					ESP_LOGW(LOGTAG, "[WARN] TorStreamRead received RELAY_TRUNCATE / RELAY_TRUNCATED.\n");
					finished = true;
					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					return false;
				}

				// Check if the stream id is the right one (otherwise is a protocol violation!)
				if (readCell->GetStreamID() != this->CURRENT_STREAM_ID) {
					ESP_LOGW(LOGTAG, "[WARN] TorStreamRead received a non-matching StreamID (current: %04X received: %04X) Destroy with protocol violation.\n", this->CURRENT_STREAM_ID, readCell->GetStreamID());
					finished = true;
					this->TearDown();
					this->Cleanup();
					return false;
				}

				// Check if this is a RELAY_END, in this case no data should be returned, just finished
				if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_END) {
					ESP_LOGD(LOGTAG, "[DEBUG] TorStreamRead received RELAY_END. Finished.\n");
					finished = true;
					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					// Exit cycle
					break; 
				}

				// Check if this is the desidered command
				if (readCell->GetRelayCommand() != BriandTorCellRelayCommand::RELAY_DATA) {
					if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
						printf("[ERR] TorStreamRead failed, received unexpected cell from exit node: %s, payload: ", BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
						readCell->PrintCellPayloadToSerial();
					}
					else {
						ESP_LOGW(LOGTAG, "[ERR] TorStreamRead failed, received unexpected cell from exit node: %s.\n", BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
					}

					finished = true;
					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					return false;
				}

				// At this point all is OK
				
				ESP_LOGD(LOGTAG, "[DEBUG] TorStreamSingle success, received %d bytes of RELAY_DATA.\n", readCell->GetPayload()->size());

				// ADD the payload
				
				buffer->insert(buffer->end(), readCell->GetPayload()->begin(), readCell->GetPayload()->end());
				
				// exit cycle
				break; 
			}
		} 
		
		// If success, keep the circuit STREAMING
		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);

		return true;
	}

	bool BriandTorCircuit::TorStreamEnd() {
		// In each case, mark circuit as NOT STREAMING anymore
		this->StatusUnsetFlag(CircuitStatusFlag::STREAMING);
		
		
		// Send a single cell with reason REASON_MISC (see tor specs 6.3)
		// Tors SHOULD NOT send any reason except REASON_MISC for a stream that they have originated.

		auto payload = make_unique<vector<unsigned char>>();
		payload->push_back(0x01);
		
		// Send the RELAY_END cell, do not check for any response or success
		this->TorStreamWriteData(BriandTorCellRelayCommand::RELAY_END, payload);

		return true;
	}

	void BriandTorCircuit::SendPadding() {
		if (this->StatusGetFlag(CircuitStatusFlag::BUILT) && 
			!this->StatusGetFlag(CircuitStatusFlag::BUSY) && 
			!this->StatusGetFlag(CircuitStatusFlag::CLOSED) && 
			!this->StatusGetFlag(CircuitStatusFlag::CLOSING) &&
			!this->StatusGetFlag(CircuitStatusFlag::STREAMING) &&
			this->paddingSentOn + 60 < BriandUtils::GetUnixTime())  
		{
			this->StatusSetFlag(CircuitStatusFlag::BUSY);
			auto tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);
			auto noBuf = tempCell->SendCell(this->sClient, false, false);
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			ESP_LOGD(LOGTAG, "[DEBUG] PADDING cell sent through circuit.\n");
			this->paddingSent++;
			this->paddingSentOn = BriandUtils::GetUnixTime();
		}
	}

	void BriandTorCircuit::TearDown(BriandTorDestroyReason reason /*  = BriandTorDestroyReason::NONE */) {
		this->StatusSetFlag(CircuitStatusFlag::CLOSING);
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

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

		if (this->sClient != nullptr && this->sClient->IsConnected()) {
			ESP_LOGD(LOGTAG, "[DEBUG] Sending DESTROY cell to Guard with reason %u\n", static_cast<unsigned char>(reason));

			auto tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::DESTROY);

			tempCell->AppendToPayload(static_cast<unsigned char>(reason));
			tempCell->SendCell(this->sClient, true, false);

			ESP_LOGD(LOGTAG, "[DEBUG] DESTROY cell sent.\n");
						
			this->sClient->Disconnect();
			this->sClient.reset();

			ESP_LOGD(LOGTAG, "[DEBUG] Circuit TearDown success.\n");
		}
		else {
			ESP_LOGD(LOGTAG, "[DEBUG] Circuit does not need TearDown.\n");
		}

		// However, always reset values to avoid misunderstandings
		// after calling this function
		this->StatusResetTo(CircuitStatusFlag::CLOSED);
		this->paddingSent = 0;
		this->CURRENT_STREAM_WINDOW = 1000;

		if (this->RSD != nullptr) {
			mbedtls_md_free(this->RSD.get());
			this->RSD.reset();
		}
	}

	void BriandTorCircuit::PrintCircuitInfo() {
		if (this->StatusGetFlag(CircuitStatusFlag::BUILT) && !(this->StatusGetFlag(CircuitStatusFlag::CLOSED) || this->StatusGetFlag(CircuitStatusFlag::CLOSING))) {
			printf("[INFO] Circuit with ID %08X is operative since Unix time %lu.\n", this->CIRCID, this->createdOn);
			printf("[INFO] You <----> G[%s] <----> M[%s] <----> E[%s] <----> Web\n", this->guardNode->nickname->c_str(), this->middleNode->nickname->c_str(), this->exitNode->nickname->c_str());
		}
		else {
			printf("[INFO] Circuit is not built, closed or in closing.\n");
		}
	}

	unsigned int BriandTorCircuit::GetCircID() {
		return this->CIRCID;
	}

	unsigned long int BriandTorCircuit::GetCreatedOn() {
		return this->createdOn;
	}

	unsigned short BriandTorCircuit::GetCurrentStreamID() {
		return this->CURRENT_STREAM_ID;
	}

	unsigned long int BriandTorCircuit::GetSentPadding() {
		return this->paddingSent;
	}

}