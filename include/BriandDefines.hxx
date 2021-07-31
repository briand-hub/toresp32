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

/* Avoid error of multiple definitions (first defined here...) */
#ifndef BRIANDDEFINES_H_ 
    #define BRIANDDEFINES_H_             

    //constexpr bool VERBOSE = true;						// show messages
    //constexpr bool DEBUG = true;							// show debug info (USE ONLY IN DEBUGGING, MUST BE SET TO false WHEN USING!)
    //constexpr unsigned int SERIAL_BAUD_RATE = 115200;		// serial monitor/console baud rate (115200 default)
    constexpr unsigned char BUILTIN_LED_MODE = 10;          // Built-in led mode: 0 = OFF, 1 = ON, 2..255 = N = blink each N*100 milliseconds
    constexpr const char* LOGTAG = "toresp32";              // Custom ESP Tag for logging
    constexpr bool CHANGE_MAC_TO_RANDOM = true;				// choose if you want to change the MAC address to a random one for improved security
    constexpr unsigned short WIFI_CONNECTION_TIMEOUT = 30;  // timeout in seconds, expired with no wifi STA connection will reboot system
    constexpr unsigned char WIFI_HOSTNAME_LEN = 8;			// random hostname length for AP/STA
    constexpr unsigned char WIFI_AP_SSID_LEN = 16;			// random ssid length for AP/STA
    constexpr unsigned char WIFI_AP_PASSWORD_LEN = 16;		// random wifi password length for AP 
    constexpr unsigned char WIFI_AP_CH = 1;					// wifichannel for AP
    constexpr unsigned char WIFI_AP_HIDDEN = 0;				// AP hidden Essid (1) or not (0)
    constexpr unsigned char WIFI_AP_MAX_CONN = 1;			// AP maximum connections (set to 1 for more security, just you) 
    constexpr unsigned char NET_CONNECT_TIMEOUT_S = 60;		// Elapsed this number of seconds, any connection is intended to be timed out!
    constexpr unsigned char NET_IO_TIMEOUT_S = 30;		    // Timeout for socket read/write operations (0 for unlimited)
    constexpr const char* NTP_SERVER = "pool.ntp.org";    	// NTP server to use
    constexpr const char HEAP_LEAK_LIMIT = 5;				// Heap consumption since system readiness more than HEAP_LEAK_LIMIT% will warn
    constexpr unsigned short TOR_CIRCUITS_KEEPALIVE = 3;	// No. of Tor circuits to be kept always open and ready
    constexpr unsigned short TOR_CIRCUITS_MAX_TIME_S = 900;	// Elapsed this time (seconds) the Tor circuit will be closed automatically.
    constexpr unsigned short TOR_CIRCUITS_MAX_REQUESTS = 15; // After N requests the Tor circuit will be closed and changed.
    constexpr unsigned char TOR_NODES_CACHE_SIZE = 35;		// No. of Tor nodes, for each type (guard/exit/middle) to keep saved. (Avoid more than 50)
    constexpr unsigned char TOR_NODES_CACHE_VAL_H = 24;		// Hours since the chache of nodes is considered OLD and must be downloaded again
    constexpr unsigned short TOR_SOCKS5_PROXY_PORT = 5001;  // Port of the Socks5 Proxy

    // Early declarations of ESP logging functions trick (see BriandEspLogging.cpp)
    
    /* This define, before including esp_log.h, allows log level higher than the settings in menuconfig  */
    #define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE

    #include <esp_idf_version.h>
    #include <esp_log.h>

    void BRIAND_SET_LOG(esp_log_level_t);

    #if ESP_IDF_VERSION <= ESP_IDF_VERSION_VAL(4, 3, 0)
        esp_log_level_t esp_log_level_get(const char*);
    #endif

#endif /* BRIANDDEFINES_H_ */