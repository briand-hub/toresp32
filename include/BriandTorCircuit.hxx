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
#include "BriandTorCell.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorRelaySearcher.hxx"
#include "BriandTorStatistics.hxx"

using namespace std;

namespace Briand {

	/**
	 * This class manage a single Tor circuit 
	*/
	class BriandTorCircuit : public BriandESPHeapOptimize {
		private:

		/** This is the circuit general status flag mask 
		 * The status can be managed by all extensions but
		 * it is mandatory to set as BUSY at the beginning of each public method
		 * and reset to not busy when returning. This will prevent tasks or threads
		 * to kill an operation (networking operation) still executing.
		*/
		unsigned short CIRCUIT_STATUS;

		protected:

		unique_ptr<Briand::BriandTorRelaySearcher> relaySearcher;
		unsigned long int createdOn;		// create timestamp
		unsigned long int paddingSent;		// no. of padding cells sent
		unsigned long int paddingSentOn;	// timestamp of last sent padding

		// Tor specific
		unsigned int CIRCID;					// the CIRCID of this circuit
		unsigned short LINKPROTOCOLVERSION; 	// the version of this circuit
		unsigned short CURRENT_STREAM_ID; 		// the current StreamID (also used for N request used)
		short CURRENT_STREAM_WINDOW;			// the current stream window. Each 100 RELAY_DATA cell are exchanged a RELAY_SENDME is needed

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

		static const char* LOGTAG;
		static const char* STREAMLOGTAG;

		/**
		 * Flags to manage circuit status
		*/
		enum CircuitStatusFlag : unsigned short {
			NONE = 			0b0000000000000000, /** No status at all, just instanced */
			BUSY = 			0b0000000000000001,	/** Busy circuit, doing something */
			BUILDING = 		0b0000000000000010, /** Doing build */
			BUILT = 		0b0000000000000100, /** Built */
			STREAM_READY = 	0b0000000000001000, /** Ready to stream */
			STREAMING = 	0b0000000000010000, /** Busy in streaming (after relay_begin, before relay_end) */
			CLOSING = 		0b0000000000100000, /** Is going to be closed */
			CLOSED = 		0b0000000001000000, /** Has been closed */
			/* ...other flags here... */
			CLEAN = 		0b0100000000000000, /** Clean, never used for any stream cell */
			DIRT = 			0b1000000000000000, /** Dirt, INSTANCE has been used at least once */
		};
		
		/** An internal additional ID, use as you wish (used by CircuitsManager class) */
		unsigned short internalID;

		/** The guard node */
		unique_ptr<Briand::BriandTorRelay> guardNode;
		/** The middle node */
		unique_ptr<Briand::BriandTorRelay> middleNode;
		/** The exit node */
		unique_ptr<Briand::BriandTorRelay> exitNode;

		BriandTorCircuit();

		~BriandTorCircuit();

		/**
		 * Builds a new circuit 
		 * @param forceTorCacheRefresh Forces the tor cache, even if valid, to be rebuilt.
		 * @return true on success
		*/ 
		bool BuildCircuit(bool forceTorCacheRefresh = false);

		/**
		 * Method streams a single cell forward, ignores PADDING cells. 
		 * StreamID must be prepared (incremented) BEFORE calling this method.
		 * Will not check RELAY_BEGIN sent, and will NOT set/unset BUSY flag.
		 * @param command The RELAY command 
		 * @param data The payload to stream
		 * @return true if sent with success, false if error.
		*/
		bool TorStreamWriteData(const BriandTorCellRelayCommand& command, const unique_ptr<vector<unsigned char>>& data);

		/**
		 * Method reads a single backward, ignores PADDING cells. 
		 * Will not check RELAY_BEGIN sent, and will NOT set/unset BUSY flag.
		 * @return Pointer to the read cell. Nullptr if error occours.
		*/
		unique_ptr<BriandTorCell> TorStreamReadData();

		/**
		 * Method streams a single cell through an operative circuit and waits for the expected RELAY command response
		 * or error (RELAY_END, DESTROY), ignores PADDING cells. StreamID must be prepared (incremented) BEFORE calling this method.
		 * Will not check RELAY_BEGIN sent, and will set/unset BUSY flag.
		 * @param command The RELAY command 
		 * @param requestPayload The payload to stream
		 * @param waitFor The command to wait for 
		 * @return Pointer to response payload or nullptr if error occours.
		*/
		unique_ptr<vector<unsigned char>> TorStreamSingle(const BriandTorCellRelayCommand& command, const unique_ptr<vector<unsigned char>>& requestPayload, const BriandTorCellRelayCommand& waitFor);

		/**
		 * Method sends a RELAY_BEGIN cell.
		 * @param hostname The hostname
		 * @param port The port
		 * @return true on success, false otherwise
		*/
		bool TorStreamStart(const string& hostname, const short& port);

		/**
		 * Method sends a RELAY_BEGIN cell.
		 * @param ipv4 The IPv4
		 * @param port The port
		 * @return true on success, false otherwise
		*/
		bool TorStreamStart(const in_addr& ipv4, const short& port);

		/**
		 * Method streams a single RELAY_DATA cell (non blocking).
		 * @param data Data to stream (MAXIMUM 498 bytes!!!)
		 * @param sent Set to false if any error occoured
		*/
		void TorStreamSend(const unique_ptr<vector<unsigned char>>& data, bool& sent);

		/**
		 * Method reads a single RELAY_DATA cell back and ADDS to the buffer
		 * @param buffer The buffer where data is ADDED. Max 498 bytes per session.
		 * @param finished The value will be set to true if RELAY_END from node is encountered.
		 * @param timeout_s The timeout (in seconds to get a valid cell response)
		 * @return true if success, false on error (ex. TRUNCATE/DESTROY).
		*/
		bool TorStreamRead(unique_ptr<vector<unsigned char>>& buffer, bool& finished, const unsigned short& timeout_s = 60);

		/**
		 * Method finishes the current data stream (write)
		 * @return true on success, false on error
		*/
		bool TorStreamEnd();

		/**
		 * Resolves an hostname through TOR (only IPv4 at moment)
		 * @param hostname the hostname to resolve
		 * @return an in_addr struct with the resolved IP Address
		*/
		const in_addr TorResolve(const string& hostname);

		/**
		 * Send a PADDING cell through circuit for keep-alive
		*/
		void SendPadding();

		/**
		 * Tears down the circuit. Also closes and resets the sClient!
		 * @param reason the reason, however should be always set to zero (NONE) if client version to avoid version leaking.
		*/
		void TearDown(BriandTorDestroyReason reason = BriandTorDestroyReason::NONE);

		/**
		 * Method returns this circuit ID
		 * @return CircID
		*/
		unsigned int GetCircID();

		/**
		 * Method returns unix timestamp since circuit creation
		 * @return Unix timestamp since circuit readyness
		*/
		unsigned long int GetCreatedOn();

		/**
		 * Method returns number of streams used (current streamID)
		 * @return Current StreamID
		*/
		unsigned short GetCurrentStreamID();

		/**
		 * Method returns number of PADDING cells sent through circuit
		 * @return Current count of PADDING cells sent
		*/
		unsigned long int GetSentPadding();

		/** Prints the circuit informations to serial. Verbose mode only */
		void PrintCircuitInfo();

		/** 
		 * Set the status flag to 0 
		 * @param flag Flag to set to 1
		*/
		void StatusSetFlag(const CircuitStatusFlag& flag);

		/** 
		 * Set the status flag to 0 
		 * @param flag Flag to set to 0 
		*/
		void StatusUnsetFlag(const CircuitStatusFlag& flag);

		/** 
		 * Set the status to zero then adds the given flag 
		 * @param flag Flag to set (unique) 
		*/
		void StatusResetTo(const CircuitStatusFlag& flag);

		/**
		 * Returns the status of a status flag
		 * @return true if set, false otherwise
		*/
		bool StatusGetFlag(const CircuitStatusFlag& flag);

		/**
		 * Returns true if the instance is doing something
		 * @return true if busy, false otherwise
		*/
		bool IsInstanceBusy();

		/**
		 * Method return a string with all status flags separeted by comma (DIRT,BUSY,BUILDING)
		 * @return string with status
		*/
		string StatusGetString();

		/** Inherited from BriandESPHeapOptimize */
		virtual void PrintObjectSizeInfo();
		/** Inherited from BriandESPHeapOptimize */
		virtual size_t GetObjectSize();
		
	};
}