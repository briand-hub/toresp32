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

// GENERAL DEFINES / SETTINGS / PARAMETERS FOR ALL FILES
// This settings could be changed if needed

#pragma once

bool VERBOSE = true;									// show all messages
bool DEBUG = true;										// show debug info (USE ONLY IN DEBUGGING, MUST BE SET TO false WHEN USING!)
constexpr unsigned int SERIAL_BAUD_RATE = 115200;		// serial monitor/console baud rate (115200 default)
constexpr bool CHANGE_MAC_TO_RANDOM = true;				// choose if you want to change the MAC address to a random one for improved security
constexpr unsigned short WIFI_CONNECTION_TIMEOUT = 120; // timeout in seconds, expired with no wifi STA connection will reboot system
constexpr unsigned char WIFI_HOSTNAME_LEN = 8;			// random hostname length for AP/STA
constexpr unsigned char WIFI_AP_SSID_LEN = 16;			// random ssid length for AP/STA
constexpr unsigned char WIFI_AP_PASSWORD_LEN = 16;		// random wifi password length for AP 
constexpr unsigned char WIFI_AP_CH = 1;					// wifichannel for AP
constexpr unsigned char WIFI_AP_HIDDEN = 0;				// AP hidden Essid (1) or not (0)
constexpr unsigned char WIFI_AP_MAX_CONN = 1;			// AP maximum connections (set to 1 for more security, just you) 
constexpr unsigned char NET_REQUEST_TIMEOUT_S = 5;		// Elapsed this number of seconds, any connection is intended to be timed out!
constexpr const char* NTP_SERVER = "pool.ntp.org";    	// NTP server to use
constexpr char HEAP_LEAK_LIMIT = 5;						// Heap consumption since system readiness more than HEAP_LEAK_LIMIT% will warn
constexpr unsigned char TOR_CIRCUITS_CACHE = 3;			// No. of Tor circuits to be kept always open and ready

