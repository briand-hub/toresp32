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

#if defined(ESP_PLATFORM)
#include <esp_timer.h>
#elif defined(__linux__)
#include "BriandEspLinuxPorting.hxx"
#else
#error "UNSUPPORTED PLATFORM (ESP32 OR LINUX REQUIRED)"
#endif

#include "BriandIDFSocketClient.hxx"
#include "BriandNet.hxx"

using namespace std;

namespace Briand {
	/** This struct represents a Tor Directory Authority */
	typedef struct _BriandTorDirAuthority {
		const char* nickname;
		const char* fingerprint;
		const char* host;
		unsigned short port;
	} BriandTorDirAuthority;
}

// DIRECTORY AUTHORITY LIST

constexpr unsigned short TOR_DIR_AUTHORITIES_NUMBER = 9;
constexpr Briand::BriandTorDirAuthority TOR_DIR_AUTHORITIES[TOR_DIR_AUTHORITIES_NUMBER] = {
	{ "moria1", "9695DFC35FFEB861329B9F1AB04C46397020CE31", "128.31.0.34", 9131 }
	, { "tor26", "847B1F850344D7876491A54892F904934E4EB85D", "86.59.21.38", 80 }
	, { "dizum", "7EA6EAD6FD83083C538F44038BBFA077587DD755", "45.66.33.45", 80 }
	, { "gabelmoo", "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281", "131.188.40.189", 80 }
	, { "maatuska", "BD6A829255CB08E66FBE7D3748363586E46B3810", "171.25.193.9", 443 }
	, { "Faravahar", "CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC", "154.35.175.225", 80 }
	, { "longclaw", "74A910646BCEEFBCD2E874FC1DC997430F968145", "199.58.81.140", 80 }
	, { "bastet", "24E2F139121D4394C54B5BCC368B3B411857C413", "204.13.164.118", 80 }
	, { "Serge", "BA44A889E64B93FAA2B114E02C2A279A8555C533", "66.111.2.131", 9030 }
	//, { "dannenberg", "", "193.23.244.244", 80}
};

// Defined after in BriandTorDirAuthority.cpp
extern unsigned short TOR_DIR_LAST_USED;

/** retrieves the best directory for speed/connection and sets to TOR_DIR_LAST_USED */
void briand_find_best_dir();