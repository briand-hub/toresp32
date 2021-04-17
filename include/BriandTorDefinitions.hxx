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

#include "BriandDefines.hxx"

/* This file contains list of classes intented to be used only as data structures, enums, constants etc. */

using namespace std;

namespace Briand {

	// Flags of a Tor relay
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

	// A Guard node must have this flags
	constexpr unsigned short TOR_FLAGS_GUARD_MUST_HAVE = 
		Briand::BriandTorRelayFlag::GUARD |
		Briand::BriandTorRelayFlag::FAST | 
		Briand::BriandTorRelayFlag::STABLE | 
		Briand::BriandTorRelayFlag::VALID | 
		Briand::BriandTorRelayFlag::V2DIR;

	// An Exit node must have this flags
	constexpr unsigned short TOR_FLAGS_EXIT_MUST_HAVE = 
		Briand::BriandTorRelayFlag::EXIT |
		Briand::BriandTorRelayFlag::FAST | 
		Briand::BriandTorRelayFlag::STABLE | 
		Briand::BriandTorRelayFlag::VALID | 
		Briand::BriandTorRelayFlag::V2DIR;
	
	// Any other node must have this flags
	constexpr unsigned short TOR_FLAGS_MIDDLE_MUST_HAVE = 
		Briand::BriandTorRelayFlag::FAST | 
		Briand::BriandTorRelayFlag::STABLE | 
		Briand::BriandTorRelayFlag::VALID | 
		Briand::BriandTorRelayFlag::V2DIR;

	// Cell commands (unsigned int = 4 bytes in link protocol 4+ or 2 bytes in link protocol version 3-)
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

		//Variable-length command values are:

		VERSIONS = 7 , 				// VERSIONS    (Negotiate proto version) (See Sec 4)
		VPADDING = 128 , 			// VPADDING  (Variable-length padding) (See Sec 7.2)
		CERTS = 129 , 				// CERTS     (Certificates)            (See Sec 4.2)
		AUTH_CHALLENGE = 130 , 		// AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
		AUTHENTICATE = 131 , 		// AUTHENTICATE (Client authentication)(See Sec 4.5)
		AUTHORIZE = 132  			// AUTHORIZE (Client authorization)    (Not yet used)
	};
	
}