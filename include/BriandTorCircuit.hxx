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

#include <BriandIDFSocketTlsClient.hxx>

#include "BriandTorDefinitions.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorRelaySearcher.hxx"

using namespace std;

namespace Briand {

	/**
	 * This class manage a single Tor circuit 
	*/
	class BriandTorCircuit {
		protected:

		unique_ptr<Briand::BriandTorRelaySearcher> relaySearcher;
		bool isBuilt;						// has been built
		bool isCreating;					// true after the success of a CREATE2
		bool isClean; 						// not used for any traffic
		bool isClosing;						// it is currently closing
		bool isClosed;						// it is closed (call destroyer and free RAM!!)
		unsigned long int createdOn;		// create timestamp

		// Tor specific
		unsigned int CIRCID;					// the CIRCID of this circuit
		unsigned short LINKPROTOCOLVERSION; 	// the version of this circuit
		unsigned short CURRENT_STREAM_ID; 		// the current StreamID

		unique_ptr<BriandIDFSocketTlsClient> sClient;	// Client used for communications

		/**
		 * Method to cleanup pointers etc. before returning after a failed operation in BuildCircuit()
		*/
		void Cleanup();

		/**
		 * Method to choose a relay with timeouts and so on to simplify code.
		 * @param relayType 0 for guard, 1 for middle, 2 for exit 
		 * @return true if success, false if there is no way to do it :(
		*/
		bool FindAndPopulateRelay(const unsigned char& relayType);

		/**
		 * Method will send the First VERSION cell to guard node and waits for In-Protocol handshake cells
		 * (CERTS/AUTHCHALLENGE/NETINFO). After that CERTS cell will be verified (certificate validation) and a response
		 * with just Netinfo (no authentication) or Certs/Authenticate/Netinfo (if authenticate) cells will be sent.
		 * WARNING : sClient MUST be initalized and connection with guard MUST be made before calling this method!
		 * @param authenticateSelf set to true if client-authentication is requested
		 * @return true if had success, false otherwise.
		*/
		bool StartInProtocolWithGuard(bool authenticateSelf = false);

		/**
		 * Method will send the CREATE2 cell to the guard node
		 * @return true if success, false otherwise
		*/
		bool Create2();

		/**
		 * Method continues to build a circuit with the next relay.
		 * @param exitNode if true, uses the EXTEND2 to the exitNode, if false extends to middleNode
		 * @return true if success, false otherwise 
		*/
		bool Extend2(bool exitNode);

		public:
		
		unique_ptr<Briand::BriandTorRelay> guardNode;
		unique_ptr<Briand::BriandTorRelay> middleNode;
		unique_ptr<Briand::BriandTorRelay> exitNode;

		BriandTorCircuit();

		~BriandTorCircuit();

		/**
		 * Builds a new circuit 
		 * @param forceTorCacheRefresh Forces the tor cache, even if valid, to be rebuilt.
		 * @return true on success
		*/ 
		bool BuildCircuit(bool forceTorCacheRefresh = false);

		// Stream functions
		// MUST check if built / closed / closing ....

		/**
		 * Method returns true if circuit is ready for stream cells
		 * @return true if circuit is built, ready, valid and not closing.
		*/
		bool IsCircuitReadyToStream();

		/**
		 * Resolves an hostname through TOR (only IPv4 at moment)
		 * @param hostname the hostname to resolve
		 * @return an in_addr struct with the resolved IP Address
		*/
		const in_addr& TorResolve(const string& hostname);

		/**
		 * Tears down the circuit. Also closes and resets the sClient!
		 * @param reason the reason, however should be always set to zero (NONE) if client version to avoid version leaking.
		*/
		void TearDown(BriandTorDestroyReason reason = BriandTorDestroyReason::NONE);

		/** Prints the circuit informations to serial. Verbose mode only */
		void PrintCircuitInfo();

	};
}