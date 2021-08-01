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

/* This file contains list of classes intented to be used only as data structures, enums, constants etc. */

using namespace std;

namespace Briand {

	/** Flags of a Tor relay */
	enum BriandTorRelayFlag : unsigned short {
		AUTHORITY		= 1 << 0,
		BADEXIT			= 1 << 1,
		EXIT			= 1 << 2,
		FAST 			= 1 << 3,
		GUARD			= 1 << 4,
		HSDIR			= 1 << 5,
		NOEDCONSENSUS	= 1 << 6,
		RUNNING			= 1 << 7,
		STABLE 			= 1 << 8,
		STABLEDESC		= 1 << 9,
		V2DIR			= 1 << 10,
		VALID			= 1 << 11
	};

	/** A Guard node must have this flags */
	constexpr unsigned short TOR_FLAGS_GUARD_MUST_HAVE = 
		Briand::BriandTorRelayFlag::GUARD |
		Briand::BriandTorRelayFlag::FAST | 
		Briand::BriandTorRelayFlag::STABLE | 
		Briand::BriandTorRelayFlag::VALID | 
		Briand::BriandTorRelayFlag::V2DIR;

	/** An Exit node must have this flags */
	constexpr unsigned short TOR_FLAGS_EXIT_MUST_HAVE = 
		Briand::BriandTorRelayFlag::EXIT |
		Briand::BriandTorRelayFlag::FAST | 
		Briand::BriandTorRelayFlag::STABLE | 
		Briand::BriandTorRelayFlag::VALID | 
		Briand::BriandTorRelayFlag::V2DIR;
	
	/** Any other node must have this flags */
	constexpr unsigned short TOR_FLAGS_MIDDLE_MUST_HAVE = 
		Briand::BriandTorRelayFlag::FAST | 
		Briand::BriandTorRelayFlag::STABLE | 
		Briand::BriandTorRelayFlag::VALID | 
		Briand::BriandTorRelayFlag::V2DIR;

	/** Cell commands (unsigned int = 4 bytes in link protocol 4+ or 2 bytes in link protocol version 3-) */
	enum BriandTorCellCommand : unsigned int {
		
		// Fixed size cells commands

		PADDING = 0 ,				// PADDING     (Padding)                 (See Sec 7.2)
        CREATE = 1 ,				// CREATE      (Create a circuit)        (See Sec 5.1)
		CREATED = 2 , 				// CREATED     (Acknowledge create)      (See Sec 5.1)
		RELAY = 3 , 				// RELAY       (End-to-end data)         (See Sec 5.5 and 6)
		DESTROY = 4 , 				// DESTROY     (Stop using a circuit)    (See Sec 5.4)
		CREATE_FAST = 5 , 			// CREATE_FAST (Create a circuit, no PK) (See Sec 5.1)
		CREATED_FAST = 6 , 			// CREATED_FAST (Circuit created, no PK) (See Sec 5.1)
		NETINFO = 8 , 				// NETINFO     (Time and address info)   (See Sec 4.5)
		RELAY_EARLY = 9 , 			// RELAY_EARLY (End-to-end data; limited)(See Sec 5.6)
		CREATE2 = 10 , 				// CREATE2    (Extended CREATE cell)    (See Sec 5.1)
		CREATED2 = 11 , 			// CREATED2   (Extended CREATED cell)    (See Sec 5.1)
		PADDING_NEGOTIATE = 12 , 	// PADDING_NEGOTIATE   (Padding negotiation)    (See Sec 7.2)

		// Variable-length command values are:

		VERSIONS = 7 , 				// VERSIONS    (Negotiate proto version) (See Sec 4)
		VPADDING = 128 , 			// VPADDING  (Variable-length padding) (See Sec 7.2)
		CERTS = 129 , 				// CERTS     (Certificates)            (See Sec 4.2)
		AUTH_CHALLENGE = 130 , 		// AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
		AUTHENTICATE = 131 , 		// AUTHENTICATE (Client authentication)(See Sec 4.5)
		AUTHORIZE = 132  			// AUTHORIZE (Client authorization)    (Not yet used)
	};
	
	/** ED25519 certificate types (CERT_TYPE field). HAS NOTHING TO DO WITH CERTS CELL TYPES! */
	enum BriandTorEd25519CerType : unsigned char {
		/* [00],[01],[02],[03] - Reserved to avoid conflict with types used in CERTS cells.*/
		/* [07] - Reserved for RSA identity cross-certification; (see section 2.3 above, and tor-spec.txt section 4.2)*/

		Ed25519_signing_key_with_an_identity_key = 4,
		TLS_link_certificate_signed_with_ed25519_signing_key = 5,
		Ed25519_authentication_key_signed_with_ed25519_signing_key = 6,
		
		OS_short_term_descriptor_signing_key = 8, // signed with blinded public key.
		OS_intro_point_auth_key_cross_certifies_descriptor_key = 9,
		ntor_onion_key_corss_certifies_ed25519_identity_key = 0xA,
		ntor_extra_encryption_key_corss_certifies_descriptor_key = 0xB
	};

	/** Circuit destroy reason */
	enum BriandTorDestroyReason : unsigned char {
		NONE = 0, 				// -- NONE            (No reason given.)
		PROTOCOL = 1, 			// -- PROTOCOL        (Tor protocol violation.)
		INTERNAL = 2, 			// -- INTERNAL        (Internal error.)
		REQUESTED = 3, 			// -- REQUESTED       (A client sent a TRUNCATE command.)
		HIBERNATING = 4, 		// -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
		RESOURCELIMIT = 5, 		// -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
		CONNECTFAILED = 6, 		// -- CONNECTFAILED   (Unable to reach relay.)
		OR_IDENTITY = 7, 		// -- OR_IDENTITY     (Connected to relay, but its OR identity was not as expected.)
		CHANNEL_CLOSED = 8, 	// -- CHANNEL_CLOSED  (The OR connection that was carrying this circuit died.)
		FINISHED = 9, 			// -- FINISHED        (The circuit has expired for being dirty or old.)
		TIMEOUT = 10, 			// -- TIMEOUT         (Circuit construction took too long)
		DESTROYED = 11, 		// -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
		NOSUCHSERVICE = 12, 	// -- NOSUCHSERVICE   (Request for unknown hidden service)
	};

	/** RELAY Cell commands */
	enum BriandTorCellRelayCommand : unsigned char {
		RELAY_BEGIN = 1, 		// 1 -- RELAY_BEGIN     [forward]
		RELAY_DATA = 2, 		// 2 -- RELAY_DATA      [forward or backward]
		RELAY_END = 3, 			// 3 -- RELAY_END       [forward or backward]
		RELAY_CONNECTED = 4, 	// 4 -- RELAY_CONNECTED [backward]
		RELAY_SENDME = 5, 		// 5 -- RELAY_SENDME    [forward or backward] [sometimes control]
		RELAY_EXTEND = 6, 		// 6 -- RELAY_EXTEND    [forward]             [control]
		RELAY_EXTENDED = 7, 	// 7 -- RELAY_EXTENDED  [backward]            [control]
		RELAY_TRUNCATE = 8, 	// 8 -- RELAY_TRUNCATE  [forward]             [control]
		RELAY_TRUNCATED = 9, 	// 9 -- RELAY_TRUNCATED [backward]            [control]
		RELAY_DROP = 10, 		// 10 -- RELAY_DROP      [forward or backward] [control]
		RELAY_RESOLVE = 11, 	// 11 -- RELAY_RESOLVE   [forward]
		RELAY_RESOLVED = 12, 	// 12 -- RELAY_RESOLVED  [backward]
		RELAY_BEGIN_DIR = 13, 	// 13 -- RELAY_BEGIN_DIR [forward]
		RELAY_EXTEND2 = 14, 	// 14 -- RELAY_EXTEND2   [forward]             [control]
		RELAY_EXTENDED2 = 15 	// 15 -- RELAY_EXTENDED2 [backward]            [control]

		// 32..40 -- Used for hidden services; see rend-spec-{v2,v3}.txt.

        // 41..42 -- Used for circuit padding; see Section 3 of padding-spec.txt.
	};        
}