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

	const char* BriandTorCircuit::LOGTAG = "briandcircuit";
	const char* BriandTorCircuit::STREAMLOGTAG = "briandstream";

	BriandTorCircuit::BriandTorCircuit() {
		this->guardNode = nullptr;
		this->middleNode = nullptr;
		this->exitNode = nullptr;
		this->relaySearcher = nullptr;

		this->createdOn = 0;

		this->CIRCID = 0;
		this->LINKPROTOCOLVERSION = 0;
		this->CURRENT_STREAM_ID = 0;
		this->LAST_ENDED_STREAM_ID = 0;
		this->CURRENT_STREAM_WINDOW = 500;
		this->CURRENT_CIRC_WINDOW = 1000;

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

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			
			switch (relayType) {
				case 0: relayS = "guard"; break;
				case 1: relayS = "middle"; break;
				case 2: relayS = "exit"; break;
				default: relayS = to_string(relayType) + "(?)";
			}
		}

		ESP_LOGD(LOGTAG, "[DEBUG] Starting search for %s node.\n", relayS.c_str());
		#endif

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

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Retrieving descriptors for %s node...\n", relayS.c_str());
			#endif

			if (tentative->FetchDescriptorsFromAuthority()) {

				if (relayType == 0) this->guardNode = std::move(tentative);
				else if (relayType == 1) this->middleNode = std::move(tentative);
				else if (relayType == 2) this->exitNode = std::move(tentative);

				done = true;
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] %s node ok.\n", relayS.c_str());
				#endif
			}
			else {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Retrieving descriptors for %s node FAILED\n", relayS.c_str());
				#endif
			}
		}

		if (!done) ESP_LOGW(LOGTAG, "[ERR] FAIL to get a valid %s node.\n", relayS.c_str());

		return done;
	}

	bool BriandTorCircuit::StartInProtocolWithGuard(bool authenticateSelf /* = false*/) {
		// Choose a first, random CircID (does not matter here, see CREATE2)
		// The first VERSIONS cell, and any cells sent before the first VERSIONS cell, always have CIRCID_LEN == 2 for backward compatibility.

		this->CIRCID = ( Briand::BriandUtils::GetRandomByte() << 8 ) + Briand::BriandUtils::GetRandomByte();

		#if !SUPPRESSDEBUGLOG
		if(esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) printf("[DEBUG] Temporary CircID = 0x%04X\n", this->CIRCID);
		#endif

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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Sending first VERSION to guard.\n");
		#endif

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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Cell response! :-D Contents (first 32 bytes): ");

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );
		#endif

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

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Link protocol version %d negotiation SUCCESS.\n", this->LINKPROTOCOLVERSION);
		}
		#endif

		// The next part of buffer should be a CERTS cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Next chunk (first 32 bytes printed): ");

		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );
		#endif

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::CERTS) {
			ESP_LOGW(LOGTAG, "[ERR] Error, expected CERTS cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got CERTS cell!\n");
		#endif
		
		if (! tempCell->SetRelayCertificatesFromCertsCell(this->guardNode) ) {
			ESP_LOGW(LOGTAG, "[ERR] CERTS cell seems not valid.\n");
			this->Cleanup();
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] Guard has %d certifcates loaded.\n", this->guardNode->GetCertificateCount());
			this->guardNode->PrintAllCertificateShortInfo();
		} 
		#endif

		if ( ! this->guardNode->ValidateCertificates() ) {
			ESP_LOGW(LOGTAG, "[ERR] CERTS cell received has invalid certificates.\n");
			this->Cleanup();
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] CERTS cell certificates validation succeded.\n");
		#endif

		// The next part of buffer should be a AUTH_CHALLENGE cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		// AUTH_CHALLENGE is used for authenticate, might not do that.

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Next chunk (first 32 bytes printed): ");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) Briand::BriandUtils::PrintByteBuffer( *(tempCellResponse.get()), 128, 32 );
		#endif

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::AUTH_CHALLENGE) {
			ESP_LOGW(LOGTAG, "[ERR] Error, expected AUTH_CHALLENGE cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got AUTH_CHALLENGE cell!\n");
		#endif

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] WARNING: AUTH_CHALLENGE cell is not handled at moment from this version.\n");
		#endif
		// TODO dont't mind for now..

		// The next part of buffer should be a NETINFO cell. Free some buffer to point to next cell. And save RAM :)

		tempCellResponse->erase(tempCellResponse->begin(), tempCellResponse->begin() + tempCell->GetCellTotalSizeBytes() );

		tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION);
		if (tempCell->GetCommand() != Briand::BriandTorCellCommand::NETINFO) {
			ESP_LOGW(LOGTAG, "[ERR] Error, expected NETINFO cell but received %s.\n", Briand::BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got NETINFO cell!\n");
		#endif

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Info: this version do not check or handle incoming NETINFO cell.\n");
		#endif
		// TODO dont't mind for now..

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got all cells needed for handshake :-)\n");
		#endif

		// The next part of buffer needs to be ignored, could be cleared and save RAM.
		// WARNING: for answer to auth all bytes received must be kept!
		tempCellResponse.reset();
		tempCell.reset();

		// After authentication....

		//
		// TODO ?
		// 

		// Answer with NETINFO CELL

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Sending NETINFO cell to guard.\n");
		#endif

		tempCell = make_unique<BriandTorCell>( this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::NETINFO );
		struct in_addr public_ip;
		inet_aton(BriandUtils::GetPublicIP().c_str(), &public_ip);
		tempCell->BuildAsNETINFO( public_ip );

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] NETINFO cell payload to send: ");
			tempCell->PrintCellPayloadToSerial();
		} 
		#endif

		tempCellResponse = tempCell->SendCell(this->sClient, false, false); // Last false: do not expect a response

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] NETINFO cell sent.\n");
		#endif

		// Freee
		tempCell.reset();
		tempCellResponse.reset();
		
		return true;
	}

	bool BriandTorCircuit::Create2() {
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Sending CREATE2 cell to guard.\n");
		#endif

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
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Failed on building cell CREATE2.\n");
			#endif
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 sent. Waiting for CREATED2.\n");
		#endif
		auto tempCellResponse = tempCell->SendCell(this->sClient, false);
		tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);
		
		if (!tempCell->BuildFromBuffer(tempCellResponse, this->LINKPROTOCOLVERSION)) {
			ESP_LOGW(LOGTAG, "[ERR] Error, response cell had invalid bytes (failed to build from buffer).\n");
			this->Cleanup();
			return false;
		}
		
		// If a DESTROY given, tell me why
		if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
			ESP_LOGW(LOGTAG, "[ERR] Error, DESTROY received! Reason = 0x%02X (%s)\n", tempCell->GetPayload()->at(0), BriandUtils::RelayTruncatedReasonToString(static_cast<BriandTorDestroyReason>(tempCell->GetPayload()->at(0))).c_str());
			this->Cleanup();
			return false;
		}

		if (tempCell->GetCommand() != BriandTorCellCommand::CREATED2) {
			ESP_LOGW(LOGTAG, "[ERR] Error, response contains %s cell instead of CREATED2. Failure.\n", BriandUtils::BriandTorCellCommandToString(tempCell->GetCommand()).c_str());
			this->Cleanup();
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got CREATED2, payload:");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
		#endif

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
		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Sending EXTEND2 cell to guard.\n");
		#endif

		// EXTEND2 is a RELAY cell! (RELAY_EARLY since link protocol v2)

		auto tempCell = make_unique<Briand::BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::RELAY_EARLY);
		
		if (exitNode) {
			if (!tempCell->BuildAsEXTEND2(*this->exitNode.get())) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Failed on building cell EXTEND2 to exit.\n");
				#endif
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}
		else {
			if (!tempCell->BuildAsEXTEND2(*this->middleNode.get())) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Failed on building cell EXTEND2 to middle.\n");
				#endif
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}

		// Prepare a StreamID of all zeros (relay commands with [control] use all-zero streamid!)
		unsigned short streamID = 0x0000;

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] StreamID is: %04X\n", streamID);
		#endif

		// After building the main contents, prepare it as a relay cell
		if (exitNode) {
			tempCell->PrepareAsRelayCell(BriandTorCellRelayCommand::RELAY_EXTEND2, streamID, this->middleNode->KEY_ForwardDigest_Df);
		}
		else {
			tempCell->PrepareAsRelayCell(BriandTorCellRelayCommand::RELAY_EXTEND2, streamID, this->guardNode->KEY_ForwardDigest_Df);
		}

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG] EXTEND2 contents before encryption: ");
			tempCell->PrintCellPayloadToSerial();
		}
		#endif

		// Then encrypt
		if (exitNode) {
			// Encrypt with middle key
			tempCell->ApplyOnionSkin(*this->middleNode);

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Applied MIDDLE onion skin, encrypted contents: ");
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
			#endif

			// Encrypt with guard keyù
			tempCell->ApplyOnionSkin(*this->guardNode);

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Applied GUARD onion skin, encrypted contents: ");
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
			#endif
		}
		else {
			// Encrypt with guard key
			tempCell->ApplyOnionSkin(*this->guardNode);

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Applied GUARD onion skin, encrypted contents: ");
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
			#endif
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 is going to be sent. Waiting for EXTENDED2.\n");
		#endif
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
			ESP_LOGW(LOGTAG, "[ERR] Error, DESTROY received! Reason = 0x%02X (%s)\n", tempCell->GetPayload()->at(0), BriandUtils::RelayTruncatedReasonToString(static_cast<BriandTorDestroyReason>(tempCell->GetPayload()->at(0))).c_str());
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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Got RELAY cell, payload:");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) tempCell->PrintCellPayloadToSerial();
		#endif

		// Decrypt payload of received cell
		if (exitNode) {
			tempCell->PeelOnionSkin(*this->guardNode);

			#if !SUPPRESSDEBUGLOG
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Removed GUARD onion skin with Kb key: ");
				BriandUtils::PrintByteBuffer(*this->guardNode->KEY_Backward_Kb.get());
				printf("[DEBUG] RELAY cell payload after decryption: ");
				tempCell->PrintCellPayloadToSerial();
			} 
			#endif

			// Check if the cell is recognized
			BriandError errCode;

			errCode = tempCell->IsRelayCellRecognized(0x0000, this->guardNode->KEY_BackwardDigest_Db);
			if (errCode == BriandError::BRIAND_ERR_OK) {
				// Have been recognized, if this is true here, an error occoured...
				tempCell->BuildRelayCellFromPayload(this->guardNode->KEY_BackwardDigest_Db);
				BriandTorCellRelayCommand unexpectedCmd = tempCell->GetRelayCommand();

				#if !SUPPRESSDEBUGLOG
				if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG] RELAY recognized at Guard, something wrong (%s), cell relay command is: %s. Payload: ", BriandUtils::BriandErrorStr(errCode), BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
					tempCell->PrintCellPayloadToSerial();
				}
				#endif

				ESP_LOGW(LOGTAG, "[ERR] Error on extending to exit node, received unexpected cell %s\n", BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
				this->TearDown();
				this->Cleanup();
				return false;
			}

			// If not, then peel out the middle node skin

			tempCell->PeelOnionSkin(*this->middleNode);

			#if !SUPPRESSDEBUGLOG
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Removed MIDDLE onion skin with Kb key: ");
				BriandUtils::PrintByteBuffer(*this->middleNode->KEY_Backward_Kb.get());
				printf("[DEBUG] RELAY cell payload after decryption: ");
				tempCell->PrintCellPayloadToSerial();
			} 
			#endif

			// Check if cell is recognized 

			errCode = tempCell->IsRelayCellRecognized(0x0000, this->middleNode->KEY_BackwardDigest_Db);
			if (errCode  != BriandError::BRIAND_ERR_OK) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Cell has not been recognized (%s), failure.\n", BriandUtils::BriandErrorStr(errCode));
				#endif
				this->TearDown();
				this->Cleanup();
				return false;
			}
		}
		else {
			tempCell->PeelOnionSkin(*this->guardNode);

			#if !SUPPRESSDEBUGLOG
			if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
				printf("[DEBUG] Removed GUARD onion skin with Kb key: ");
				BriandUtils::PrintByteBuffer(*this->guardNode->KEY_Backward_Kb.get());
				printf("[DEBUG] RELAY cell payload after decryption: ");
				tempCell->PrintCellPayloadToSerial();
			} 
			#endif

			// Check if cell is recognized 

			BriandError errCode = tempCell->IsRelayCellRecognized(0x0000, this->guardNode->KEY_BackwardDigest_Db);
			if (errCode != BriandError::BRIAND_ERR_OK) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(LOGTAG, "[DEBUG] Cell has not been recognized (%s), failure.\n", BriandUtils::BriandErrorStr(errCode));
				#endif
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
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Expected EXTENDED2 but received %s\n", BriandUtils::BriandTorRelayCellCommandToString(tempCell->GetRelayCommand()).c_str());
			#endif
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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] EXTENDED2 Success, circuit has now a new hop\n");
		#endif

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

		// Statistics
		auto buildStartTime = esp_timer_get_time();

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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Starting relay search.\n");
		#endif

		// GUARD
		if (!this->FindAndPopulateRelay(0)) { 
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			BriandTorStatistics::STAT_NUM_CACHE_GUARD_MISS++;
			return false;  
		}

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->guardNode->PrintRelayInfo();
		ESP_LOGD(LOGTAG, "[DEBUG] Starting relay search for middle node.\n");
		#endif
		
		// MIDDLE
		if (!this->FindAndPopulateRelay(1)) { 
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			BriandTorStatistics::STAT_NUM_CACHE_MIDDLE_MISS++;
			return false;  
		} 

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->middleNode->PrintRelayInfo();
		ESP_LOGD(LOGTAG, "[DEBUG] Starting relay search for exit node.\n");
		#endif

		// EXIT
		if (!this->FindAndPopulateRelay(2)) { 
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			BriandTorStatistics::STAT_NUM_CACHE_EXIT_MISS++;
			return false;  
		} 

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->exitNode->PrintRelayInfo();
		ESP_LOGD(LOGTAG, "[DEBUG] Guard node ready, start sending VERSION to guard.\n");
		#endif

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
			BriandTorStatistics::STAT_NUM_GUARD_CONN_ERR++;
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] Connected to guard node.\n");
		#endif

		/** Steps validation */
		bool stepDone = false;

		// Here I will use the IN-PROTOCOL HANDSHAKE
		stepDone = this->StartInProtocolWithGuard(false); // false = do not answer with self authenticate

		if (!stepDone) {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude InProtocol with guard.\n");
			#endif
			this->Cleanup();
			return false;
		}

		// If the relay do not have an Ed25519 identity, the CREATE2 will fail.
		// This version does not support old CREATE.

		if (this->guardNode->certRSAEd25519CrossCertificate == nullptr) {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] The guard is missing the Ed25519 identity certificate so a CREATE2 is impossible.\n");
			#endif
			this->Cleanup();
			return false;
		}


		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] All information complete. Starting creating the circuit with CREATE2.\n");
		#endif

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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] NEW CircID: 0x%08X \n", this->CIRCID);
		#endif

		// CREATE/CREATE2

		stepDone = this->Create2();

		if (!stepDone) {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude CREATE2 with guard.\n");
			#endif
			this->TearDown();
			BriandTorStatistics::STAT_NUM_CREATE2_FAIL++;
			return false;
		}

		// Clear no more needed certificates to save RAM
		this->guardNode->ResetCertificates();
		this->middleNode->ResetCertificates();
		this->exitNode->ResetCertificates();

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] CREATE2 success. Extending to Middle node.\n");
		#endif

		// EXTEND2 to middle

		stepDone = this->Extend2(false);

		if (!stepDone) {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude EXTEND2 with middle node.\n");
			#endif
			this->TearDown();
			BriandTorStatistics::STAT_NUM_EXTEND2_FAIL++;
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 with Middle success. Extending to Exit node.\n");
		#endif

		// EXTEND2 to exit

		stepDone = this->Extend2(true);

		if (!stepDone) {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Failed to conclude EXTEND2 with exit node.\n");
			#endif
			this->TearDown();
			BriandTorStatistics::STAT_NUM_EXTEND2_FAIL++;
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(LOGTAG, "[DEBUG] EXTEND2 with Exit success. All done!!\n");
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->PrintCircuitInfo();
		#endif

		// Circuit is now OK!

		this->StatusResetTo(CircuitStatusFlag::BUILT);
		this->StatusSetFlag(CircuitStatusFlag::STREAM_READY);
		this->StatusSetFlag(CircuitStatusFlag::CLEAN);
		
		this->createdOn = BriandUtils::GetUnixTime();

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) this->PrintCircuitInfo();
		#endif

		// Statistics
		// esp_timer_get_time() returns microseconds!
		if (BriandTorStatistics::STAT_BUILD_TIME_MAX < (esp_timer_get_time() - buildStartTime)/1000) {
			BriandTorStatistics::STAT_BUILD_TIME_MAX = (esp_timer_get_time() - buildStartTime)/1000;
		}
		
		return true;
	}

	bool BriandTorCircuit::TorStreamWriteData(const BriandTorCellRelayCommand& command, const unique_ptr<vector<unsigned char>>& data, const bool& overrideSID /*= false*/, const unsigned short& SID /*= 0*/) {
		// Circuit must be ready to stream
		this->StatusUnsetFlag(CircuitStatusFlag::CLEAN);

		// Statistics
		auto startTime = esp_timer_get_time();

		if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamWriteData called but circuit is not built and ready to stream.\n", this->CIRCID);
			return false;
		}

		if (data == nullptr) {
			ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamWriteData called with NULL request payload.\n", this->CIRCID);
			return false;
		}

		// prepare the basic cell
		auto tempCell = make_unique<Briand::BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::RELAY);

		// Add the payload and prepare the cell
		if (!tempCell->AppendBytesToPayload(*data.get())) {
			ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamWriteData called with too large payload.\n", this->CIRCID);
			return false;
		}

		tempCell->PrepareAsRelayCell(command, ( overrideSID ? SID : this->CURRENT_STREAM_ID ), this->exitNode->KEY_ForwardDigest_Df);

		// Encrypt with exit key
		tempCell->ApplyOnionSkin(*this->exitNode);
		// Encrypt with middle key
		tempCell->ApplyOnionSkin(*this->middleNode);
		// Encrypt with guard key
		tempCell->ApplyOnionSkin(*this->guardNode);

		// Send cell but and do not wait any answer.
		tempCell->SendCell(this->sClient, false, false);

		// Update statistics
		// esp_timer_get_time() returns microseconds
		BriandTorStatistics::STAT_TOR_SEND_TIME_AVG = (BriandTorStatistics::STAT_TOR_SEND_TIME_AVG*BriandTorStatistics::STAT_TOR_SEND_N) + ((esp_timer_get_time() - startTime)/1000);
		BriandTorStatistics::STAT_TOR_SEND_N++;
		BriandTorStatistics::STAT_TOR_SEND_TIME_AVG /= BriandTorStatistics::STAT_TOR_SEND_N;

		return true;
	}

	unique_ptr<BriandTorCell> BriandTorCircuit::TorStreamReadData() {
		/* 
			Cycle introduced in order to pop old streamid cells (closed circuits) that were sent by the relay before the RELAY_END received from me.
			In this case a new cycle will run and the old, unreceived cells will be treated.
		*/
		
		// Assume true to enter the cycle
		bool wasPreviousStream = true;
		
		while (wasPreviousStream) {

			// Assume not need to re-do cycle
			wasPreviousStream = false;

			// Circuit must be ready to stream
			this->StatusUnsetFlag(CircuitStatusFlag::CLEAN);

			// Statistics
			auto startTime = esp_timer_get_time();

			if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
				ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamReadData called but circuit is not built and ready to stream.\n", this->CIRCID);
				return nullptr;
			}

			// Read the socket, as all RELAY/DESTROY/PADDING cells are fixed-length cells, this is easy...
			this->sClient->SetReceivingBufferSize(514); 
			auto tempData = this->sClient->ReadData(true);
			// Sometimes truncated data occours, so check all 514 bytes has been read
			if (tempData->size() < 514) {
				unsigned short remainingBytes = 514 - static_cast<unsigned short>(tempData->size());
				
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[WARN][%08X] Received %zu bytes instead of 514 expected. Reading remaining %hu bytes.\n", this->CIRCID, tempData->size(), remainingBytes);
				#endif

				this->sClient->SetReceivingBufferSize(remainingBytes); 
				auto lostData = this->sClient->ReadData(true);
				tempData->insert(tempData->end(), lostData->begin(), lostData->end());
				this->sClient->SetReceivingBufferSize(514);
			}

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamReadData %d bytes read.\n", this->CIRCID, tempData->size());
			#endif

			// If zero bytes have been read, peer disconnected! better to tear down...
			if (tempData == nullptr || tempData->size() == 0) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamReadData tearing down circuit because probably disconnected or timed-out.\n", this->CIRCID);
				#endif

				this->TearDown();
				this->Cleanup();
				return nullptr;
			}
			
			// Build the basic cell from received data
			auto tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::PADDING);

			if (!tempCell->BuildFromBuffer(tempData, this->LINKPROTOCOLVERSION)) {
				ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamReadData error, response cell had invalid bytes (failed to build from buffer).\n", this->CIRCID);
				// During a stream this error leds to fatal error: the digest will not be anymore valid! So tear down!
				this->TearDown();
				this->Cleanup();
				return nullptr;
			}

			// If cell does not belong to this circuit, ignore it.
			if (tempCell->GetCircID() != this->CIRCID) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamReadData received a cell with a different CircID (this is %08X, received %08X), ignoring.\n", this->CIRCID, this->CIRCID, tempCell->GetCircID());
				#endif
				return std::move(tempCell);
			}

			// If a DESTROY given must tear down, tell me why
			if (tempCell->GetCommand() == BriandTorCellCommand::DESTROY) {
				ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamReadData error, DESTROY received! Reason = 0x%02X (%s)\n", this->CIRCID, tempCell->GetPayload()->at(0), BriandUtils::RelayTruncatedReasonToString(static_cast<BriandTorDestroyReason>(tempCell->GetPayload()->at(0))).c_str());
				
				BriandTorStatistics::SaveStatistic(tempCell);
				
				this->TearDown();
				this->Cleanup();
				return std::move(tempCell);
			}

			// If it is a RELAY cell, must be decrypted.
			if (tempCell->GetCommand() == BriandTorCellCommand::RELAY) {
				// Cell recognization 
				BriandError errCode;

				// Peel out the guard skin
				tempCell->PeelOnionSkin(*this->guardNode.get());
				errCode = tempCell->IsRelayCellRecognized(this->CURRENT_STREAM_ID, this->guardNode->KEY_BackwardDigest_Db);
				
				if (errCode == BriandError::BRIAND_ERR_OK) {
					// If is recognized here, an error occoured.
					tempCell->BuildRelayCellFromPayload(this->guardNode->KEY_BackwardDigest_Db);
					BriandTorCellRelayCommand unexpectedCmd = tempCell->GetRelayCommand();

					#if !SUPPRESSDEBUGLOG
					if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
						printf("[DEBUG][%08X] TorStreamReadData RELAY recognized at Guard, something wrong, cell relay command is: %s. Payload: ", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
						tempCell->PrintCellPayloadToSerial();
					}
					#endif

					ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamReadData error, received unexpected cell from guard node: %s\n", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());

					return std::move(tempCell);
				}

				// Peel out the middle skin
				tempCell->PeelOnionSkin(*this->middleNode.get());
				errCode = tempCell->IsRelayCellRecognized(this->CURRENT_STREAM_ID, this->middleNode->KEY_BackwardDigest_Db);
				
				if (errCode == BriandError::BRIAND_ERR_OK) {
					// If is recognized here, an error occoured.
					tempCell->BuildRelayCellFromPayload(this->middleNode->KEY_BackwardDigest_Db);
					BriandTorCellRelayCommand unexpectedCmd = tempCell->GetRelayCommand();

					#if !SUPPRESSDEBUGLOG
					if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
						printf("[DEBUG][%08X] TorStreamReadData RELAY recognized at Middle, something wrong, cell relay command is: %s. Payload: ", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());
						tempCell->PrintCellPayloadToSerial();
					}
					#endif

					ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStream error, received unexpected cell from middle node: %s\n", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(unexpectedCmd).c_str());

					return std::move(tempCell);					
				}

				// Peel out the exit skin, now the cell MUST be recognized...
				tempCell->PeelOnionSkin(*this->exitNode.get());
				errCode = tempCell->IsRelayCellRecognized(this->CURRENT_STREAM_ID, this->exitNode->KEY_BackwardDigest_Db);
				
				// Check if this cells comes from a PREVIOUSLY CLOSED Stream if errCode != OK
				for (unsigned short i = 1; i < this->CURRENT_STREAM_ID && !wasPreviousStream && errCode != BriandError::BRIAND_ERR_OK; i++) {
					auto errCodeOld = tempCell->IsRelayCellRecognized(i, this->exitNode->KEY_BackwardDigest_Db);
					if (errCodeOld == BriandError::BRIAND_ERR_OK) {
						wasPreviousStream = true;

						printf("*** [%08X] TorStreamReadData Cell belongs to a previous stream with id %04X (current is %04X)\n", this->CIRCID, i, this->CURRENT_STREAM_ID);
					
						#if !SUPPRESSDEBUGLOG
						ESP_LOGD(STREAMLOGTAG, "[%08X] TorStreamReadData Cell belongs to a previous stream with id %04X (current: %04X). Restarting to read.\n", this->CIRCID, i, this->CURRENT_STREAM_ID);
						#endif
					}
				}

				
				if (wasPreviousStream) {
					//
					// TODO : maybe update backward digest!??!?!
					//

					printf("*** [%08X] TorStreamReadData CYCLE CONTINUE FOR ME StreamID=%04X\n", this->CIRCID, this->CURRENT_STREAM_ID);

					continue;
				}

				if (!wasPreviousStream && errCode != BriandError::BRIAND_ERR_OK) {
					// If is NOT recognized here, an error occoured.
					
					printf("*** [%08X] TorStreamReadData RELAY NOT recognized at Exit (%s). StreamID=%04X, raw payload at exit: ", this->CIRCID, BriandUtils::BriandErrorStr(errCode), this->CURRENT_STREAM_ID);
					tempCell->PrintCellPayloadToSerial();

					#if !SUPPRESSDEBUGLOG
					if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
						printf("[DEBUG][%08X] TorStreamReadData RELAY NOT recognized at Exit (%s). StreamID=%04X, raw payload at exit: ", this->CIRCID, BriandUtils::BriandErrorStr(errCode), this->CURRENT_STREAM_ID);
						tempCell->PrintCellPayloadToSerial();
					}
					#endif

					ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStream error, unrecognized cell from exit node.\n", this->CIRCID);

					return nullptr;
				}

				// Here cell is recognized

				// Build informations (decrypted payload etc.)
				if (!tempCell->BuildRelayCellFromPayload(this->exitNode->KEY_BackwardDigest_Db)) {
					ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamReadData error on rebuilding RELAY cell informations from exit node, invalid response cell.\n", this->CIRCID);
					return nullptr;
				}

				// If this is a RELAY_DATA remember to update the window!
				if (tempCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_DATA) {
					// Update current window
					this->CURRENT_STREAM_WINDOW--;
					this->CURRENT_CIRC_WINDOW--;

					// Check if a new RELAY_SENDME (Stream-level) is required
					if (this->CURRENT_STREAM_WINDOW <= 450) {

						// Re-increment by 50 the window (now, because async threads could do all at same time!)
						this->CURRENT_STREAM_WINDOW += 50;

						#if !SUPPRESSDEBUGLOG
						ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] A RELAY_SENDME is required.\n", this->CIRCID);
						#endif

						/*
							The RELAY_SENDME payload contains the following:

							VERSION     [1 byte]
							DATA_LEN    [2 bytes]
							DATA        [DATA_LEN bytes]

							--------- NOTE: in this case this is a STREAM sendme between edge nodes!

							Edge nodes use RELAY_SENDME cells to implement end-to-end flow
							control for individual connections across circuits. Similarly to
							circuit-level flow control, edge nodes begin with a window of cells
							(500) per stream, and increment the window by a fixed value (50)
							upon receiving a RELAY_SENDME cell. Edge nodes initiate RELAY_SENDME
							cells when both a) the window is <= 450, and b) there are less than
							ten cell payloads remaining to be flushed at that edge.

							Stream-level RELAY_SENDME cells are distinguished by having nonzero
							StreamID. They are still empty; the body still SHOULD be ignored.
						*/

						auto sendMePayload = make_unique<vector<unsigned char>>();
						//sendMePayload->reserve(BriandTorCell::PAYLOAD_LEN); // reserve some bytes
						sendMePayload->push_back(0x01); // version 1 authenticated cell

						if (tempCell->GetRelayCellDigest() == nullptr) {
							ESP_LOGE(STREAMLOGTAG, "[ERR][%08X] ERROR! A RELAY_DATA is received but FullDigest field is not populated for the RELAY_SENDME cell.\n", this->CIRCID);
							return std::move(tempCell);
						}

						// Append the size
						sendMePayload->push_back(static_cast<unsigned char>(tempCell->GetRelayCellDigest()->size()));

						// Append the received cell digest (that is the last RELAY_DATA received cell)
						sendMePayload->insert(sendMePayload->end(), tempCell->GetRelayCellDigest()->begin(), tempCell->GetRelayCellDigest()->end());

						// This is a Stream-sendme cell, so StreamID remains

						// Send the cell
						if (!this->TorStreamWriteData(BriandTorCellRelayCommand::RELAY_SENDME, sendMePayload)) {
							ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] RELAY_SENDME cell NOT sent (errors). Circuit will be torn down.\n", this->CIRCID);
							this->TearDown();
							return nullptr;
						}
						else {
							#if !SUPPRESSDEBUGLOG
							ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] RELAY_SENDME sent.\n", this->CIRCID);
							#endif
						}
					}
					else if (this->CURRENT_CIRC_WINDOW <= 900) {
						// Use else to avoid digest updated by a previous sendme of stream-level!

						// Re-increment by 100 the circuit window (now, because async threads could do all at same time!)
						this->CURRENT_CIRC_WINDOW += 100;

						#if !SUPPRESSDEBUGLOG
						ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] A RELAY_SENDME (circuit-level) is required.\n", this->CIRCID);
						#endif

						/*
							The RELAY_SENDME payload contains the following:

							VERSION     [1 byte]
							DATA_LEN    [2 bytes]
							DATA        [DATA_LEN bytes]

							A circuit-level RELAY_SENDME cell always has its StreamID=0.

						*/

						auto sendMePayload = make_unique<vector<unsigned char>>();
						//sendMePayload->reserve(BriandTorCell::PAYLOAD_LEN); // reserve some bytes
						sendMePayload->push_back(0x01); // version 1 authenticated cell

						if (tempCell->GetRelayCellDigest() == nullptr) {
							ESP_LOGE(STREAMLOGTAG, "[ERR][%08X] ERROR! A RELAY_DATA is received but FullDigest field is not populated for the RELAY_SENDME (circuit-level) cell.\n", this->CIRCID);
							return std::move(tempCell);
						}

						// Append the size
						sendMePayload->push_back(static_cast<unsigned char>(tempCell->GetRelayCellDigest()->size()));

						// Append the received cell digest (that is the last RELAY_DATA received cell)
						sendMePayload->insert(sendMePayload->end(), tempCell->GetRelayCellDigest()->begin(), tempCell->GetRelayCellDigest()->end());

						// Send the cell : This is a Circuit-Sendme cell, so StreamID must be zero
						if (!this->TorStreamWriteData(BriandTorCellRelayCommand::RELAY_SENDME, sendMePayload, true, 0x0000)) {
							ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] RELAY_SENDME (circuit-level) cell NOT sent (errors). Circuit will be torn down.\n", this->CIRCID);
							this->TearDown();
							return nullptr;
						}
						else {
							#if !SUPPRESSDEBUGLOG
							ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] RELAY_SENDME (circuit-level) sent.\n", this->CIRCID);
							#endif
						}

						printf("*** [%08X] RELAY_SENDME (circuit-level) sent. Circ win=%hu\n", this->CIRCID, this->CURRENT_CIRC_WINDOW);
					}
				}
			}

			tempData.reset();
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamReadData success.\n", this->CIRCID);
			#endif

			// Update statistics
			// esp_timer_get_time() return microseconds
			BriandTorStatistics::STAT_TOR_RECV_TIME_AVG = (BriandTorStatistics::STAT_TOR_RECV_TIME_AVG*BriandTorStatistics::STAT_TOR_RECV_N) + ((esp_timer_get_time() - startTime)/1000);
			BriandTorStatistics::STAT_TOR_RECV_N++;
			BriandTorStatistics::STAT_TOR_RECV_TIME_AVG /= BriandTorStatistics::STAT_TOR_RECV_N;

			return std::move(tempCell);

		} 

		// Out of this cycle should return nullptr (never should arrive there!!)

		return nullptr;
	}

	unique_ptr<vector<unsigned char>> BriandTorCircuit::TorStreamSingle(const BriandTorCellRelayCommand& command, const unique_ptr<vector<unsigned char>>& requestPayload, const BriandTorCellRelayCommand& waitFor) {
		unique_ptr<vector<unsigned char>> response = nullptr;

		// Set circuit busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);
		
		// Write data
		if (!this->TorStreamWriteData(command, requestPayload)) {
			ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamSingle error on writing request.\n", this->CIRCID);
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return response;
		}

		// Read data until the desidered command is found or an error is thrown.
		do {
			auto readCell = this->TorStreamReadData();

			// If nullptr => error
			if (readCell == nullptr) {
				ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamSingle error on reading response cell.\n", this->CIRCID);
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return response;
			}

			// If PADDING cell or CIRCID not matching, ignore it.
			if (readCell->GetCircID() != this->CIRCID || readCell->GetCommand() == BriandTorCellCommand::PADDING) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamSingle ignoring cell.\n", this->CIRCID);
				#endif
				continue;
			}

			// Check if the stream id is the right one (otherwise is a protocol violation!)
			if (readCell->GetStreamID() != this->CURRENT_STREAM_ID && readCell->GetStreamID() != 0x0000) {
				ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamRead received a non-matching StreamID (current: %04X received: %04X) Destroy with protocol violation.\n", this->CIRCID, this->CURRENT_STREAM_ID, readCell->GetStreamID());
				this->TearDown();
				this->Cleanup();
				return response;
			}

			// If DESTROY, return error.
			if (readCell->GetCommand() == BriandTorCellCommand::DESTROY) {
				ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamSingle received circuit DESTROY.\n", this->CIRCID);
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
					ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamSingle received RELAY_TRUNCATE / RELAY_TRUNCATED, reason = %s.\n", this->CIRCID, BriandUtils::RelayTruncatedReasonToString(static_cast<BriandTorDestroyReason>(readCell->GetPayload()->at(0))).c_str());
					this->TearDown();
					this->Cleanup();
					return response;
				}

				// If RELAY_SENDME then continue the cycle
				if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_SENDME) 
				{
					#if !SUPPRESSDEBUGLOG
					ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamSingle received RELAY_SENDME.\n", this->CIRCID);
					#endif

					//
					// TODO : Something to do?
					//

					continue;
				}

				// Check if this is the desidered command
				if (readCell->GetRelayCommand() != waitFor) {

					#if !SUPPRESSDEBUGLOG
					if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
						printf("[ERR][%08X] TorStreamSingle failed, received unexpected cell from exit node: %s, payload: ", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
						readCell->PrintCellPayloadToSerial();
					}
					#endif

					// If RELAY_END show reason
					if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_END && readCell->GetPayload() != nullptr && readCell->GetPayload()->size() > 0) {
						ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamSingle failed, received unexpected cell from exit node: %s reason: %s.\n", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str(), BriandUtils::RelayEndReasonToString( static_cast<BriandTorRelayEndReason>(readCell->GetPayload()->at(0)) ).c_str());
					}
					else {
						ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamSingle failed, received unexpected cell from exit node: %s.\n", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
					}

					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					return response;
				}

				// At this point all is OK

				#if !SUPPRESSDEBUGLOG
				if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
					printf("[DEBUG][%08X] TorStreamSingle success, received %s, payload: ", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
					readCell->PrintCellPayloadToSerial();
				}
				#endif

				// Take payload and return, that's all!
				response = make_unique<vector<unsigned char>>();
				//response->reserve(BriandTorCell::PAYLOAD_LEN); // reserve some bytes
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
			ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamStart error: circuit still streaming or not ready to stream.\n", this->CIRCID);
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

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] Sending RELAY_RESOLVE cell for hostname <%s>.\n", this->CIRCID, hostname.c_str());
		#endif

		auto requestPayload = make_unique<vector<unsigned char>>();
		//requestPayload->reserve(BriandTorCell::PAYLOAD_LEN); // reserve some bytes

		for (const char& c: hostname) {
			requestPayload->push_back(static_cast<unsigned char>(c));
		}
		requestPayload->push_back(0x00); // NUL terminating byte

		// Increment streamid 
		this->CURRENT_STREAM_ID++;

		auto response = this->TorStreamSingle(BriandTorCellRelayCommand::RELAY_RESOLVE, requestPayload, BriandTorCellRelayCommand::RELAY_RESOLVED);
		if (response == nullptr) {
			ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorResolve error, failure on streaming tor request.\n", this->CIRCID);
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
				ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorResolve: host could not be resolved, error code = %02X\n", this->CIRCID, type);
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

		#if !SUPPRESSDEBUGLOG
		if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
			printf("[DEBUG][%08X] Found IPv4 address: 0x%08X / %s\n", this->CIRCID, resolved.s_addr, BriandUtils::IPv4ToString(resolved).c_str());
		}
		#endif

		this->StatusUnsetFlag(CircuitStatusFlag::STREAMING);
		this->StatusUnsetFlag(CircuitStatusFlag::BUSY);

		return resolved;
	}

	bool BriandTorCircuit::TorStreamStart(const string& hostname, const short& port) {
		// Mark busy
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		// If circuit is busy or not ready to stream, error
		if (this->StatusGetFlag(CircuitStatusFlag::STREAMING) || !this->StatusGetFlag(CircuitStatusFlag::STREAM_READY)) {
			ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamStart error: circuit still streaming or not ready to stream.\n", this->CIRCID);
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		// Increment streamid 
		this->CURRENT_STREAM_ID++;

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamStart streamid %hu.\n", this->CIRCID, this->CURRENT_STREAM_ID);
		#endif

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
		payload->reserve(BriandTorCell::PAYLOAD_LEN); // reserve some bytes
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
			ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamStart error: cannot connect to required destination.\n", this->CIRCID);
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamStart success.\n", this->CIRCID);
		#endif

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
			ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamStart error: circuit not streaming (missing TorStreamStart()? not built?).\n", this->CIRCID);
			sent = false;
			return;
		}

		#if !SUPPRESSDEBUGLOG
		ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamSend sending data forward to circuit with StreamID %hu.\n", this->CIRCID, this->CURRENT_STREAM_ID);
		#endif

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
			ESP_LOGE(STREAMLOGTAG, "[ERR][%08X] TorStreamRead error: buffer argument is not instanced!\n", this->CIRCID);
			finished = true;
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		// Circuit here SHOULD be streaming from a previous TorStreamStart()
		if (!this->StatusGetFlag(CircuitStatusFlag::STREAM_READY) || !this->StatusGetFlag(CircuitStatusFlag::STREAMING)) {
			ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamRead error: circuit not streaming (missing TorStreamStart()? not built?).\n", this->CIRCID);
			finished = true;
			this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
			return false;
		}

		// Read until a single significative cell from the stream (a RELAY cell)
		while (1) {
			auto readCell = this->TorStreamReadData();

			// Check timeout
			if (BriandUtils::GetUnixTime() > now+timeout_s) {
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamRead TIMEOUT (%hu seconds).\n", this->CIRCID, timeout_s);
				#endif
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return false;
			}

			// If nullptr => error
			if (readCell == nullptr) {
				ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamRead error on reading response cell.\n", this->CIRCID);
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				return false;
			}

			// If PADDING cell or CIRCID not matching, ignore it.
			if (readCell->GetCircID() != this->CIRCID || readCell->GetCommand() == BriandTorCellCommand::PADDING) {
				BriandTorStatistics::SaveStatistic(readCell);
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamRead ignoring cell.\n", this->CIRCID);
				#endif
				this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
				continue;
			}

			// If DESTROY, return error.
			if (readCell->GetCommand() == BriandTorCellCommand::DESTROY) {
				BriandTorStatistics::SaveStatistic(readCell);
				ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamRead received circuit DESTROY.\n", this->CIRCID);
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
					BriandTorStatistics::SaveStatistic(readCell);
					ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamRead received RELAY_TRUNCATE / RELAY_TRUNCATED, reason = %s. StreamID is %04X, Stream Window is %hu, Circ Windows is %hu\n", this->CIRCID, BriandUtils::RelayTruncatedReasonToString(static_cast<BriandTorDestroyReason>(readCell->GetPayload()->at(0))).c_str(), this->CURRENT_STREAM_ID, this->CURRENT_STREAM_WINDOW, this->CURRENT_CIRC_WINDOW);
					finished = true;
					this->TearDown();
					this->Cleanup();
					return false;
				}

				// Check if the stream id is the right one (otherwise is a protocol violation!)
				if (readCell->GetStreamID() != this->CURRENT_STREAM_ID) {
					BriandTorStatistics::SaveStatistic(readCell);
					ESP_LOGW(STREAMLOGTAG, "[WARN][%08X] TorStreamRead received a non-matching StreamID (current: %04X received: %04X) Destroy with protocol violation.\n", this->CIRCID, this->CURRENT_STREAM_ID, readCell->GetStreamID());
					finished = true;
					this->TearDown();
					this->Cleanup();
					return false;
				}

				// Check if this is a RELAY_END, in this case no data should be returned, just finished
				if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_END) {
					BriandTorStatistics::SaveStatistic(readCell);
					
					#if !SUPPRESSDEBUGLOG
					ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamRead received RELAY_END. Finished.\n", this->CIRCID);
					#endif
					
					finished = true;
					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					// Exit cycle
					break; 
				}

				// If RELAY_SENDME then continue the cycle
				if (readCell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_SENDME) 
				{
					BriandTorStatistics::SaveStatistic(readCell);
					#if !SUPPRESSDEBUGLOG
					ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamSingle received RELAY_SENDME, ignoring.\n", this->CIRCID);
					#endif

					//
					// TODO : Something to do?
					//

					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					continue;
				}

				// Check if this is the desidered command
				if (readCell->GetRelayCommand() != BriandTorCellRelayCommand::RELAY_DATA) {
					BriandTorStatistics::SaveStatistic(readCell);

					#if !SUPPRESSDEBUGLOG
					if (esp_log_level_get(STREAMLOGTAG) == ESP_LOG_DEBUG) {
						printf("[ERR][%08X] TorStreamRead failed, received unexpected cell from exit node: %s, payload: ", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());
						readCell->PrintCellPayloadToSerial();
					}
					#endif
					
					ESP_LOGW(STREAMLOGTAG, "[ERR][%08X] TorStreamRead failed, received unexpected cell from exit node: %s.\n", this->CIRCID, BriandUtils::BriandTorRelayCellCommandToString(readCell->GetRelayCommand()).c_str());

					finished = true;
					this->StatusUnsetFlag(CircuitStatusFlag::BUSY);
					return false;
				}

				// At this point all is OK
				
				#if !SUPPRESSDEBUGLOG
				ESP_LOGD(STREAMLOGTAG, "[DEBUG][%08X] TorStreamSingle success, received %d bytes of RELAY_DATA.\n", this->CIRCID, readCell->GetPayload()->size());
				#endif

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
		
		// Update: send only if streamid is set (>0) to avoid errors
		
		if (this->CURRENT_STREAM_ID > this->LAST_ENDED_STREAM_ID) {
			// Send a single cell with reason REASON_MISC (see tor specs 6.3)
			// Tors SHOULD NOT send any reason except REASON_MISC for a stream that they have originated.

			auto payload = make_unique<vector<unsigned char>>();
			payload->push_back(0x01);
			
			// Send the RELAY_END cell, do not check for any response or success
			this->TorStreamWriteData(BriandTorCellRelayCommand::RELAY_END, payload);

			this->LAST_ENDED_STREAM_ID = this->CURRENT_STREAM_ID;

			printf("*** SENT A RELAY_END BY MY SIDE ON CIRCUIT %08X STREAMID %08X.\n", this->CIRCID, this->CURRENT_STREAM_ID);
		}

		// Update: wait that the end node receive it. (1 second max)
		vTaskDelay(1000 / portTICK_PERIOD_MS);

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
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] PADDING cell sent through circuit.\n");
			#endif
			this->paddingSent++;
			this->paddingSentOn = BriandUtils::GetUnixTime();
		}
	}

	void BriandTorCircuit::TearDown(BriandTorDestroyReason reason /*  = BriandTorDestroyReason::NONE */) {
		this->StatusSetFlag(CircuitStatusFlag::CLOSING);
		this->StatusSetFlag(CircuitStatusFlag::BUSY);

		BriandTorStatistics::SaveStatistic(reason);

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
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Sending DESTROY cell to Guard with reason %u\n", static_cast<unsigned char>(reason));
			#endif

			auto tempCell = make_unique<BriandTorCell>(this->LINKPROTOCOLVERSION, this->CIRCID, BriandTorCellCommand::DESTROY);

			tempCell->AppendToPayload(static_cast<unsigned char>(reason));
			tempCell->SendCell(this->sClient, true, false);

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] DESTROY cell sent.\n");
			#endif
						
			this->sClient->Disconnect();
			this->sClient.reset();

			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Circuit TearDown success.\n");
			#endif
		}
		else {
			#if !SUPPRESSDEBUGLOG
			ESP_LOGD(LOGTAG, "[DEBUG] Circuit does not need TearDown.\n");
			#endif
		}

		// However, always reset values to avoid misunderstandings
		// after calling this function
		this->StatusResetTo(CircuitStatusFlag::CLOSED);
		this->paddingSent = 0;
		this->CURRENT_STREAM_WINDOW = 500;
		this->CURRENT_CIRC_WINDOW = 1000;
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

	size_t BriandTorCircuit::GetObjectSize() {
		size_t oSize = 0;

		oSize += sizeof(*this);
		oSize += sizeof(this->exitNode) + (this->exitNode == nullptr ? 0 : this->exitNode->GetObjectSize());
		oSize += sizeof(this->guardNode) + (this->guardNode == nullptr ? 0 : this->guardNode->GetObjectSize());
		oSize += sizeof(this->middleNode) + (this->middleNode == nullptr ? 0 : this->middleNode->GetObjectSize());
		oSize += sizeof(this->relaySearcher) + (this->relaySearcher == nullptr ? 0 : this->relaySearcher->GetObjectSize());
		oSize += sizeof(this->sClient) + (this->sClient == nullptr ? 0 : this->sClient->GetObjectSize());

		return oSize;
	}

	void BriandTorCircuit::PrintObjectSizeInfo() {
		printf("sizeof(*this) = %zu\n", sizeof(*this));
		printf("sizeof(this->exitNode) = %zu\n", sizeof(this->exitNode) + (this->exitNode == nullptr ? 0 : this->exitNode->GetObjectSize()));
		printf("sizeof(this->guardNode) = %zu\n", sizeof(this->guardNode) + (this->guardNode == nullptr ? 0 : this->guardNode->GetObjectSize()));
		printf("sizeof(this->middleNode) = %zu\n", sizeof(this->middleNode) + (this->middleNode == nullptr ? 0 : this->middleNode->GetObjectSize()));
		printf("sizeof(this->relaySearcher) = %zu\n", sizeof(this->relaySearcher) + (this->relaySearcher == nullptr ? 0 : this->relaySearcher->GetObjectSize()));
		printf("sizeof(this->sClient) = %zu\n", sizeof(this->sClient) + (this->sClient == nullptr ? 0 : this->sClient->GetObjectSize()));

		printf("TOTAL = %zu\n", this->GetObjectSize());
	}

}