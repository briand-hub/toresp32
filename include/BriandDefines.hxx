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
// MOVED HERE ALL #include directives in order to simplify files
// This settings could be changed if needed

/* Avoid error of multiple definitions (first defined here...) */
#ifndef BRIANDDEFINES_H_ 
    #define BRIANDDEFINES_H_        

    /* If set to 1, NO DEBUG log for components will be compiled. To have debug log on just set to 0 (#define SUPPRESSDEBUGLOG 0) */
    #define SUPPRESSDEBUGLOG 1

    constexpr unsigned char BUILTIN_LED_MODE = 1;               // Built-in led mode: 0 = OFF, 1 = ON
    constexpr bool CHANGE_MAC_TO_RANDOM = true;				    // choose if you want to change the MAC address to a random one for improved security
    constexpr unsigned short WIFI_CONNECTION_TIMEOUT = 90;      // timeout in seconds, expired with no wifi STA connection will reboot system
    constexpr unsigned char WIFI_HOSTNAME_LEN = 8;			    // random hostname length for AP/STA
    constexpr unsigned char WIFI_AP_SSID_LEN = 16;			    // random ssid length for AP/STA
    constexpr unsigned char WIFI_AP_PASSWORD_LEN = 16;		    // random wifi password length for AP 
    constexpr unsigned char WIFI_AP_CH = 1;					    // wifichannel for AP
    constexpr unsigned char WIFI_AP_HIDDEN = 0;				    // AP hidden Essid (1) or not (0)
    constexpr unsigned char WIFI_AP_MAX_CONN = 1;			    // AP maximum connections (set to 1 for more security, just you) 
    constexpr unsigned char NET_CONNECT_TIMEOUT_S = 60;		    // Elapsed this number of seconds, any connection is intended to be timed out!
    constexpr unsigned char NET_IO_TIMEOUT_S = 30;		        // Timeout (seconds) for socket read/write operations (0 for unlimited)
    constexpr const char* NTP_SERVER = "pool.ntp.org";    	    // NTP server to use
    constexpr bool TOR_CIRCUITS_RANDOM_SKIP = false;            // Skip random bytes of consensus to increase randomness of cache (however could not be a good choice for speed)
    constexpr unsigned short TOR_CIRCUITS_KEEPALIVE = 8;	    // No. of Tor circuits to be kept always open and ready (avoid more than 8 on ESP Platform without spiram!)
    constexpr unsigned short TOR_CIRCUITS_MAX_TIME_S = 900;	    // Elapsed this time (seconds) the Tor circuit will be closed automatically.
    constexpr unsigned short TOR_CIRCUITS_MAX_REQUESTS = 1000;  // After N requests the Tor circuit will be closed and changed.
    constexpr unsigned char TOR_NODES_CACHE_SIZE = 20;		    // No. of Tor nodes, for each type (guard/exit/middle) to keep saved. (higher parameter leds to higher cache download!)
    constexpr unsigned char TOR_NODES_CACHE_VAL_H = 24;		    // Hours since the chache of nodes is considered OLD and must be downloaded again
    constexpr unsigned char TOR_SOCKS5_PROXY_MAX_CONN = 67;     // % of maximum accepted connection accepted by proxy (Max = (TOR_SOCKS5_PROXY_MAX_CONN/100.0)*TOR_CIRCUITS_KEEPALIVE) (avoid more than 67% on ESP Platform without spiram!)
    constexpr unsigned short TOR_SOCKS5_PROXY_PORT = 80;        // Default port of the Socks5 Proxy
    constexpr unsigned short TOR_SOCKS5_PROXY_TIMEOUT_S = 30;   // Timeout in seconds the Socks5 Proxy select/read/write calls
    
    /** The following setting will define the size of the TOR_MUST_HAVE_PORTS array. */
    constexpr const unsigned char TOR_MUST_HAVE_PORTS_SIZE = 1;
    /** The following setting will make relay searcher to choose only exit nodes that accept the listed ports. */
    constexpr const unsigned short TOR_MUST_HAVE_PORTS[TOR_MUST_HAVE_PORTS_SIZE] = { 443 };
    

    // Includes needed (with linux porting enabled)

    /* Standard C++ libraries */
    #include <iostream>
    #include <memory>
    #include <vector>
    #include <sstream>
    #include <climits>
    #include <time.h>
    #include <fstream>
    #include <iomanip>
    #include <algorithm>
    #include <future>
    #include <mutex>
    #include <queue>

    /* mbedtls and libsodium libraries */
    #include <sodium.h>
    #include <mbedtls/md.h>
    #include <mbedtls/md_internal.h>
    #include <mbedtls/ecdh.h>
    #include <mbedtls/ssl.h>
    #include <mbedtls/entropy.h>
    #include <mbedtls/ctr_drbg.h>
    #include <mbedtls/error.h>
    #include <mbedtls/certs.h>
    #include <mbedtls/rsa.h>
    #include <mbedtls/pk.h>
    #include <mbedtls/base64.h>
    #include <mbedtls/ecp.h>

    #ifdef MBEDTLS_HKDF_C
        #include <mbedtls/hkdf.h>
    #endif

    #if defined(ESP_PLATFORM)

        /* Framework libraries */
        #include <freertos/FreeRTOS.h>
        #include <freertos/task.h>
        #include <esp_system.h>
        #include <esp_wifi.h>
        #include <esp_event.h>
        #include <esp_idf_version.h>
        #include <esp_int_wdt.h>
        #include <esp_task_wdt.h>
        #include <nvs_flash.h>
        #include <driver/gpio.h>
        #include <esp_spiffs.h>
        #include <esp_sntp.h>
        #include <esp_timer.h>
        #include <esp_tls.h>
        #include <esp_pthread.h>
        // HW Accelleration by ESP32 cryptographic hardware
        // #include <mbedtls/aes.h> gives linker error!
        #include <aes/esp_aes.h>
        #include <lwip/err.h>
        #include <lwip/sockets.h>
        #include <lwip/sys.h>
        #include <lwip/netdb.h>
        #include <lwip/inet.h>
        #include <lwip/ip_addr.h>
        #include <sys/stat.h>

        /* Custom specific libraries */
        #include "BriandESPDevice.hxx"
        #include "BriandESPHeapOptimize.hxx"
        #include "BriandIDFWifiManager.hxx"
        #include "BriandIDFSocketClient.hxx"
        #include "BriandIDFSocketTlsClient.hxx"
        // CJSON NOT NEEDED ANYMORE #include <cJSON.h>

        // Early declarations of ESP logging functions trick (see BriandEspLogging.cpp)
        
        /* This define, before including esp_log.h, allows log level higher than the settings in menuconfig  */
        #ifndef LOG_LOCAL_LEVEL
            #define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
        #endif

        #include <esp_log.h>

        void BRIAND_SET_LOG(const char*, esp_log_level_t);

        #if ESP_IDF_VERSION <= ESP_IDF_VERSION_VAL(4, 3, 0)
            esp_log_level_t esp_log_level_get(const char*);
        #endif

    #elif defined(__linux__)
        /* Framework libraries */
        #include <cstdio>
        #include <cstdlib>
        #include <unistd.h>
        #include <sys/stat.h>

        /* Custom specific libraries */
        #include "BriandEspLinuxPorting.hxx"
        #include "BriandESPDevice.hxx"
        #include "BriandESPHeapOptimize.hxx"
        #include "BriandIDFWifiManager.hxx"
        #include "BriandIDFSocketClient.hxx"
        #include "BriandIDFSocketTlsClient.hxx"
        // CJSON NOT NEEDED ANYMORE #include <cJSON.h>
        
        // #include <mbedtls/aes.h> gives linker error on ESP_PLATFORM!
        #include <mbedtls/aes.h>

        /* On linux platform make mbedtls settings similar to ESP ones */
        #include <mbedtls/config.h>
        
        #ifdef MBEDTLS_SSL_IN_CONTENT_LEN
        #undef MBEDTLS_SSL_IN_CONTENT_LEN
        #endif
        #define MBEDTLS_SSL_IN_CONTENT_LEN 4096
        
        #ifdef MBEDTLS_SSL_OUT_CONTENT_LEN
        #undef MBEDTLS_SSL_OUT_CONTENT_LEN
        #endif
        #define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

        /* Re-define project-specific IDF functions */
        void BRIAND_SET_LOG(const char*, esp_log_level_t);
        typedef mbedtls_aes_context esp_aes_context;
        #define esp_aes_init mbedtls_aes_init
        #define esp_aes_free mbedtls_aes_free
        #define esp_aes_setkey mbedtls_aes_setkey_enc
        #define esp_aes_crypt_ctr mbedtls_aes_crypt_ctr
        
    #else 
        #error "UNSUPPORTED PLATFORM (ESP32 OR LINUX REQUIRED)"
    #endif

    
    // STACK SIZE OPTIMIZATIONS


    #if SUPPRESSDEBUGLOG
        #define STACK_TorEsp32 4096
        #define STACK_HeapStats 768
        #define STACK_StaCheck 1024
        #define STACK_MgrInst 5120
        #define STACK_TorProxy 2816
        #define STACK_TorProxyReq 4096
        #define STACK_StreamWR 3584
        #define STACK_StreamRD 4096
    #else
        #define STACK_TorEsp32 4096
        #define STACK_HeapStats 1024
        #define STACK_StaCheck 1280
        #define STACK_MgrInst 5120
        #define STACK_TorProxy 3072
        #define STACK_TorProxyReq 4096
        #define STACK_StreamWR 4096
        #define STACK_StreamRD 4096
    #endif

    
    // ERROR CODES

    enum BriandError : short {
        /* No error */
        BRIAND_ERR_NONE = 0,
        BRIAND_ERR_OK = 1,

        /* Network errors: [-1; -999] */


        /* Circuit errors [-1000; -1999] */


        /* Cell generic errors [-2000; -2999] */

        BRIAND_ERR_INSUFFICIENT_PAYLOAD_BYTES = -2000,
        
        /* Relay cell errors [-3000; -3999] */

        BRIAND_ERR_NOT_RELAY_CELL = -3000,
        BRIAND_ERR_RECOGNIZED_NOT_ZERO = -3001,
        BRIAND_ERR_STREAMID_NOT_MATCHING_NOR_ZERO = -3002,
        BRIAND_ERR_DIGEST_NOT_MATCHING = -3003,
        
        /* Searcher/cache errors [-4000; -4999] */

        BRIAND_ERR_GUARD_CACHE_INVALID = -4000,
        BRIAND_ERR_MIDDLE_CACHE_INVALID = -4001,
        BRIAND_ERR_EXIT_CACHE_INVALID = -4002,
        BRIAND_ERR_CACHE_INVALID_LINE = -4003

    };

#endif /* BRIANDDEFINES_H_ */

