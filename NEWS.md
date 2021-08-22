# Development status

## Next steps

* Place BriandError management on strategic debugging functions
* Consider switch to nonblocking cache file read
* Implement a vector of nodes.
* Authenticate cell? => Prepare stub method to authenticate client

## 2021-08-21

* Possible bug in tor relay searcher: too much rebuild cache requests... SOLVED!
* Possible bug in stream: after some cells exchanged, seems unrecognize all. Maybe due to the additional bytes download?
* Separate circuit log from stream log to debug better
* Socks5 Proxy better task management (simplified, using also make_shared to avoid invalid reads)
* Started to use error codes


## 2021-08-19

* Implemented circuit statistics
* Added support for ESP32-S2 and testing PSram
* Upgraded LibBriandIDF to test with ESP Wrover and ESP32S2
* Added and edited sdkconfig files
* Additional settings tuning are required to work with SPI RAM (ESP WRover, ESP32-S2 **only**):
  * (SPI RAM settings) *Try to allocate memories of WiFi and LWIP in SPIRAM firstly. If failed, allocate internal memory* required 
  * *Component config -> Wi-Fi -> Max Number of Wifi static TX buffers = 32*
  * *Component config -> Wi-Fi -> Max number of WiFi cache TX buffers = 32*
* Added more statistics, compare with Linux porting.
* Added suppress-log
* Added random-skip lines to consensus download and file flushing
* Removed parameter *Component config -> FreeRTOS -> ENABLED Place FreeRTOS functions into Flash* I think causing cache failures and frequent download.
* Better cache access with waiting search requests
* Better stack sizes when log suppressed
* Possible bug in tor relay searcher: too much rebuild cache requests... 

## 2021-08-18

* Solved the BIIIIIIIG bug in the while() that was causing heap paaaaaaaain :/ left the set parameters in previous news. Reset the previously commented "// reserve some bytes"

  * Start-up free heap ~285KB (now moved BEFORE CircuitsManager startup)
  * With 5 built circuits, not connected to, AP, no proxy used: HEAP FREE: 124628 / 369256 bytes. MAX FREE 213564 MIN FREE 124072 LARGEST FREE BLOCK: 65536
  * With 5 circuits built, connected to AP, no proxy used: HEAP FREE: 121316 / 369256 bytes. MAX FREE 213564 MIN FREE 119620 LARGEST FREE BLOCK: 65536
  * With 5 circuits built, connected to AP, proxy after use with curl: HEAP FREE: 103508 / 369256 bytes. MAX FREE 213564 MIN FREE 101624 LARGEST FREE BLOCK: 65536
  * With 5 circuits built, connected to AP, proxy after use with firefox: HEAP FREE: 

* Swtiched now to 6 circuits (reset the QUEUE length to 100% causes crash but parameters were fine)
* New loglevel command for any tag, "log TAG N/E/", each object has its own now in order to limit output.
* Removed previous byte reservations for vector<> and changed back to dynamic buffers and structs.
* Testing with 8 circuits and cache increased to 255 nodes (~60KB files), but needed to change Wi-Fi dynamic buffers to 64 to avoid AP disconnections (with 40 disconnects when using proxy)

  * Start-up free heap still ~285KB 
  * With 8 built circuits, not connected to, AP, no proxy used: HEAP FREE: 89708 / 368696 bytes. MAX FREE 213128 MIN FREE 83076 LARGEST FREE BLOCK: 65536
  * With 8 circuits built, connected to AP, no proxy used: HEAP FREE: 67584 / 368696 bytes. MAX FREE 213128 MIN FREE 62532 LARGEST FREE BLOCK: 16384
  * With 8 circuits built, connected to AP, proxy after use with curl: HEAP FREE: 108384 / 368696 bytes. MAX FREE 213128 MIN FREE 62532 LARGEST FREE BLOCK: 65536
  * With 8 circuits built, connected to AP, proxy after use with firefox: HEAP FREE: 87740 / 368696 bytes. MAX FREE 213128 MIN FREE 42680 LARGEST FREE BLOCK: 32768
* New cache size of 255 nodes does not increase so much spiffs usage and makes things more reliable in relay searching
* Added settings TOR_MUST_HAVE_PORTS in order to select only the exit nodes that accepts connections to the listed ports. This leds to download full consensus!
* Added command to change proxy port
* Removed all old Onionoo commented implementations
* Reset cache size to 100 nodes, too much time required when exit port filtering is needed!
* No. of max open sockets setting promoted to 16.

## 2021-08-17

* Working to new release 1.1.0 with faster proxy
* Moved to 5 maximum open circuits (need more memory, AP connections troubles), should also be enough for new proxy handlers with async read/write operations.
* Removed led blinking (just off always if parameter set, or ON when circuits ready)
* New proxy requires a higher timeout, set TOR_SOCKS5_PROXY_TIMEOUT_S to 30 seconds.
* New proxy AWESOME: from 40seconds to 13seconds on the testing web page!
* removed DELETED methods and old stuff
* Redefined task priorities, and set the following settings in order to avoid connection errors to AP (found on https://github.com/espressif/esp-idf/issues/2915):

  *Component config -> Wi-Fi -> DISABLED WiFi AMPDU TX*

  *Component config -> Wi-Fi -> DISABLED WiFi AMPDU RX*

* Need to track *heap_caps_get_largest_free_block()* crashes are probably due to heap fragmentation!
* Moved ResetCertificates() after the CREATE2 to save RAM before Extending.
* Noted that if Firefox has proxy info, a fresh restarted ESP when connected to AP will be annoied by a lot of requests and crashes for out of memory!
  This is due to heap fragmentation, there are still ~12KB minimum of free heap but they could be fragmented (noted malloc() failed exceptions).
  To solve issue, following settings have been changed and the maximum dimension for listen() on proxy is HALF of the available circuits. Settings have been 
  changed by reading [lwIP minimum ram](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/lwip.html) and [WiFi memory optimization](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi.html#wifi-buffer-usage) documentations. For Wi-Fi buffer the Default configuration has been used. However some parameters were diffferent and found AP connection issues, so follows full parameters list.

  Also the TorProxy on client accept/read/write operation needed modifications: static buffers where possible, increased operation delay to 300ms. Vectors there have been pre-allocated using a reserve() called with the maximum needed. This technique has been used also elsewhere (find it by searching "// reserve some bytes" comment in code).

  Results after this operation: 

  * RAM:   [=         ]  11.1% (used 36472 bytes from 327680 bytes)
  * Flash: [======    ]  62.1% (used 1301493 bytes from 2097152 bytes)
  * Start-up free heap ~300KB (now moved BEFORE CircuitsManager startup)
  * With 5 built circuits, not connected to, AP, no proxy used: HEAP FREE: 116616 / 369256 bytes. MAX FREE 213564 MIN FREE 114456 LARGEST FREE BLOCK: 65536
  * With 5 circuits built, connected to AP, no proxy used: HEAP FREE: 123300 / 369496 bytes. MAX FREE 230236 MIN FREE 120792 LARGEST FREE BLOCK: 65536
  * With 5 circuits built, connected to AP, proxy in use with curl: HEAP FREE: 99700 / 369256 bytes. MAX FREE 213612 MIN FREE 86808 LARGEST FREE BLOCK: 65536
  * With 5 circuits built, connected to AP, proxy in use with firefox: MIN free = , MAX free = , LARGEST FREE BLOCK = 

  **DISABLED PSRAM as ESP32 in version LolinD32 has not. Could be enabled when WRover used. Backup of old file sdkconfig.lolin_d32.backup and done a fresh Menuconfig**

  *TESTING WITH NORMAL CPU SPEED 160 vs 240 to check if crashes are related to this*

  *Component config -> Wi-Fi -> Max Number of Wifi static RX buffers = 16 (16 fine with 6 circuits keep-alive)*

  *Component config -> Wi-Fi -> Max Number of Wifi dynamic RX buffers = 32 (32 fine with 6 circuits keep-alive)*

  *Component config -> Wi-Fi -> Type of WiFi TX buffers = Dynamic (Static) //this setting could not be changed from Static if PSRAM enabled*

  *Component config -> Wi-Fi -> Max Number of Wifi dynamic/static TX buffers = 32 (32 fine with 6 circuits keep-alive)*

  *Component config -> Wi-Fi -> DISABLED WiFi AMPDU TX // for connet-to-ap issues*

  *Component config -> Wi-Fi -> DISABLED WiFi AMPDU RX // for connet-to-ap issues*

  *Component config -> Wi-Fi -> DISABLED WiFi RX IRAM speed optimization*

  *Component config -> Wi-Fi -> DISABLED WiFi IRAM speed optimization*

  *Component config -> Wi-Fi -> left ENABLED WPA-3-Personal*

  *Component config -> LWIP -> ICMP -> ENABLED answer to pings (useful for debugging)*

  *Component config -> LWIP -> DISABLED LWIP IRAM optimization*

  *Component config -> LWIP -> Max Number of open sockets = 12*

  *Component config -> LWIP -> TCPIP task receive mail box size = 32*

  *Component config -> LWIP -> IPV6 left enabled, could save a lot (~7KB RAM) but one day I will implement IPv6*

  *Component config -> LWIP -> TCP -> Maximum active TCP Connections = 16*
  
  *Component config -> LWIP -> TCP -> Maximum listening TCP Connections = 16*

  *Component config -> LWIP -> TCP -> Maximum segment size (MSS) = 1024 (default was 1440)*

  *Component config -> LWIP -> TCP -> Default send buffer size = 2440 (>2xMSS as required, default was 5770)*
  
  *Component config -> LWIP -> TCP -> Default receive window size = 2440 (>2xMSS as required, default was 5770)*

  *Component config -> LWIP -> TCP -> Default TCP receive mail box size = 6 (default was 6)*

  *Component config -> LWIP -> ICMP -> ENABLED answer to pings (useful)*

  *Component config -> LWIP -> ENABLED Enable reassembly incoming fragmented IP4 packets (due to small fragments, assert() fails sometimes)*

  *Component config -> LWIP -> ENABLED Enable reassembly incoming fragmented IP6 packets (due to small fragments, assert() fails sometimes)*

  *Component config -> LWIP -> DISABLED Enable LWIP ASSERT checks (could cause crashes)*

  *Component config -> LWIP -> ICMP -> ENABLED answer to pings (useful)*

  *Component config -> LWIP -> TEMPORARY ENABLED SOME SETTINGS in Enable LWIP Debug (useful)*

  *Component config -> Wi-Fi Provisioning manager -> Max Wi-Fi Scan result entries = 6*

  *Component config -> FreeRTOS -> FreeRTOS assertions -> Print and continue (useful for debugging)*

  *Component config -> mbedTLS -> TLS maximum incoming fragment length = 4096 (default was 16384)*

  *Component config -> mbedTLS -> TLS maximum outgoing fragment length = 2048 (default was 4096)*

* Removed old sdkconfig files to avoid misunderstandings
* Added a REQUEST_QUEUE to limit to 2/3 of the alive circuits the Proxy requests (otherwise a lack of memory and crash could happen)
* Lowered some stack sizes for tasks, however need to test in DEBUG mode because of more stack required with printf's
* Removed shutdown() for sockets as it is causing fatal error on LWIP TCP/IP stack (see https://github.com/espressif/esp-idf/issues/2931).

## 2021-08-15

* Added task monitoring command and enabled config parameter USE_TRACE_FACILITY 
* Testing task stack usage on ESP system: done optimizations
* Testing STA auto disconnect cause: found powersave (now set to off by default) and this error:
	
  *I (919907) wifi:bcn_timout,ap_probe_send_start*
	
  *I (923657) wifi:ap_probe_send over, resett wifi status to disassoc*
  
  solved by changing staCheckHealth() with just a simple *esp_wifi_connect()* call on auto-reconnect code.
* Optimized mbedTLS library memory usage by setting following options as ENABLED in menuconfig:
    
    *Component config -> mbedTLS -> Using dynamic TX/RX buffer*
    
    *Component config -> mbedTLS -> Using dynamic TX/RX buffer -> Free SSL peer certificate after...*
    
    *Component config -> mbedTLS -> Using dynamic TX/RX buffer -> Free private key after...*
    
    *Component config -> mbedTLS -> Using dynamic TX/RX buffer -> Free private key after... -> Free SSL ca certificate after...*
	  
    *Component config -> mbedTLS -> Using dynamic TX/RX buffer -> Free private key after...*

  BEFORE: each circuit requires ~30KB of heap (~4KB for object, ~26KB for mbedtls client communications). MIN FREE HEAP ~10KB
  
  AFTER: each circuit requires ~10KB of heap (~4KB for object, ~6KB for mbedtls client communications). MIN FREE HEAP ~80KB with 3 built circuits
* Increased default no. of circuits (TOR_CIRCUITS_KEEPALIVE) to 8 (tested, no low memory and network works, otherwise sockets/ap connections seems not to work well)
  
  *Component config -> Wi-Fi -> Max Number of WiFi static RX/TX bufers = 16 (10 was default)*
  
  *Component config -> Wi-Fi -> WiFi AMPDU TX BA window size = 16 (6 was default)*
  
  *Component config -> Wi-Fi -> WiFi AMPDU RX BA window size = 16 (6 was default)*
  
  *Component config -> LWIP -> Max Number of open sockets = 16 (10 was default)*
  
  *Component config -> LWIP -> TCP -> Maximum active TCP Connections = 16 (10 was default)*
  
  *Component config -> LWIP -> TCP -> Maximum listening TCP Connections = 16 (10 was default)*
  
  *Component config -> LWIP -> TCP -> Maximum segment size (MSS) = 1440 (kept default)*
  
  *Component config -> LWIP -> TCP -> Default send buffer size = 2880 (2xMSS as required, default was 5770)*
  
  *Component config -> LWIP -> TCP -> Default receive window size = 2880 (2xMSS as required, default was 5770)*
  
  *Component config -> LWIP -> TCP -> Default TCP receive mail box size = 16 (default was 6)*
* PROXY Authentication user/psw

## 2021-08-08

* Need to change a little Socks5Proxy not catching client disconnect for http request and keeping socket opened. (main thread + one thread per accept())
* Removed COMMANDID and leak testing, switching to full socks5 proxy
* Moving to another cache implementation using microdescriptors from Authorities
* Added heap monitor to meminfo command
* Moved to microdescriptor cache and more efficient FetchDescriptorsFromAuthorities with readLine method of LibBriandIDF
* Added STA command for connect/disconnect and auto-reconnect
* Something is eating all heap (found with 3 built circuits goes below 10.000bytes free)
* Optimized use of vector->data() instead of copy to the "old" buffer style

## 2021-08-07

* First streaming success! used curl in linux env: *curl http://ifconfig.me/all.json --socks5-hostname 127.0.0.1:5001*
* Seems something is broken on the FetchDescriptors response (truncated at half), need debug.
* Seems something wrong with bind() and listen() in socks5 need debug
* Added ESP Exception decoder for command line *java -jar EspStackTraceDecoder.jar <Path to xtensa-lx106-elf-addr2line> <Elf-File> <Dump of Exception>*
* Last crashes are due to low memory (causing also STA reset...) with cache of 30 nodes and 2 working circuits seems stable
* First streaming success also with CURL/ESP32!

## 2021-08-01

* Debugging with linux porting and valgrind: resolved some bugs
* Testing with valgrind
* Found that torcache has too poor nodes and sometimes the same is chosen
* Found that crashes are due to task calling objects that are "busy" and are destroyed before finishing.
* Added circuit status flags
* Better task scheduling resolved crashes (on linux, still to deep test on esp32), remains one related to blocking I/O on cache files
* Solved wrong file on RelaySearcher

## 2021-07-31

* Random crashes still persist (when restarting tor circuits manager task), need deep debugging
* Finished SOCKS5 class
* Changed public IP request to IPFY API
* Arrived ESP-Prog debugging board, testing and debugging!!
* Upgraded LibBriandIDF, working to linux porting for better debugging and tests.

## 2021-07-25

* Random crashes still persist (when restarting tor circuits manager task), need deep debugging
* Started to write SOCKS5 class
* Changes to Stream methods, more simple and raw.

## 2021-07-18

* IDF updated: Platformio update framework-espidf 3.40300.0 (4.3.0)
* Changed logging system with ESP default
* Tested Circuits Manager, working
* Added test tor command and tested PADDING on built circuits, hostname resolution. All OK!
* BUG: Sometimes tasks launch sys_check_timeouts errors, related to tcpip thread. Solution could be one task for all circuits with delayed building

## 2021-07-17

* Bug solved on onionoo URL separator
* Wrote Stream method
* Wrote TorResolve method
* Wrote Circuits Manager class

## 2021-05-29
* EXTEND with exit now working!! The problem was AES not keeping IV/Nonce not updated and wrong backard digest calculation.
* Found problem with digest update, resolved
* Backward digest verification and update
* Digesting function bug/misuse correction adding mbedtls right methods
* Added method to verify relay cell before building fields

## 2021-05-22

* EXTEND2 working, success on building the first hop!
* Resolved EXTEND2 failures due to a mistake on fingerprint length

## 2021-05-15

* Library upgrade and improvements
* Re-testing CREATE2 failure
* Solved CREATE2 (error due to mbedtls big-endian bytes instead of little-endian)
* Added RELAY cell basic handling
* Added last_working_directory auth as static
* Updated NTOR handshake digest fields error

## 2021-05-08
## Switch to IDF complete
RAM:   [=         ]  12.0% (used 39440 bytes from 327680 bytes)
Flash: [======    ]  61.7% (used 1293890 bytes from 2097152 bytes)

**SdkConfig changes**:

	Enabled Component config->HTTP Server->WebSocket server support
	
  Enabled Component config->HTTP Server->ESP_HTTPS_SERVER support
	
	Enabled Component config->mbedTLS->HKDF algortithm

	Enabled Component config->mbedTLS->Expiry verification
	
  Disabled Component config->mbedTLS->Support TLS 1.0

	Compiler options -> Optimize for size
	
  Compiler options -> Assertion level -> Silent
	
  Compiler options -> Enable C++ Exceptions
	
  Component config -> Log Output set to error only

## 2021-05-02
### SWITCH TO IDF Framework
- [x] platformio.ini modifications
- [x] Enabled mbedtls hkdf
- [x] Partition table
- [x] Code changes from Serial. to standard printf / cout
- [x] Rewrite JSON uing framework cJSON
- [x] Rewrite

## 2021-05-01
* Base64 fix for the omitted '='/'==' ending in ntor key, causing handshake failures
* Key exchange was wrong, doing corrections
* Rename CertificateUtils class to CryptoUtils class

### The big problem
Found that Arduino framework with the latest IDF and C++17 has too much size on RAM limited to 320KB. When generating curve25519 keys an error about BIGNUM trying to allocate too much memory has been thrown and there is no way to avoid. 

However seems that IDF framework (from Espressif) is a much better and flexible solution. With some tests I got the proof. IDF has builtin, fully configurable libraries also to manage JSON if needed. So switching the project to IDF it's a must. Found how to use C++17, easy.

For educational purposes, the **current, unusable** project sources will be placed in a different branch called "main-arduino-not-working".

## 2021-04-25
* Added authoritiy directory list for descriptors query after reading dir-spec.txt
* Debug/Verbose available as constexpr only
* Switched to hxx + cpp structure (things are going to be complicated)
* Added realay descriptor NTOR Onion Key for handshakes
* Test new cache success
* Added function to avoid same-family nodes
* Changes and optimizations
* Send NETINFO cell after CERTS cell authentication

## 2021-04-24

* Switch to a better file-cached Onionoo lists (also according to the *"...we build circuits when we have enough directory info to do it..."*)
* Remove limit and old methods in RelaySearcher class
* Wrote certificate validation methods (one is still pending for unclear statement _"The certified key in the Link certificate matches the link key that was used to negotiate the TLS connection"_) **I had a lot of pain with CERTS cell!!!**


## No enough flash space first problem [SOLVED]
Today first error: The program size (1 393 964 bytes) is greater than maximum allowed (1310720 bytes). 
AFTER REMOVAL OF ARDUINOJSON => Error: The program size (1 385 416 bytes) is greater than maximum allowed (1310720 bytes).
### Possible solutions and checks: 
- [x] Remove ArduinoJson library (check weight) and switch to a better Onionoo request & caching (~250KB max per file/request leds to at least 750KB filesystem free space)
Not the right way! Program size with almost no changes
- [x] Use LittleFS rather than SPIFFS (check weight)
Not the right way! Think no significative changes
- [x] Use another partition table and check file system free space is enough for future improvements
Needed at least 750KB free SPIFFS storage. No OTA required. 

That's it! Switching to no_ota.csv in platformio.ini leds to:

Flash: [=======   ]  66.5% (used 1393964 bytes from 2097152 bytes) 

maybe if this error will take plae again switch to huge_app.csv (no ota, program up to 3.145.728 bytes and SPIFFS of ~900KB)

## 2021-04-23

* Got first space problem!
* Added an utility class for certificate utilities if the mbedtls library will change in future
* Solved mbedtls signature verification (see https://github.com/ARMmbed/mbedtls/issues/4400)
* Added expcted or not response parameter to raw request method
* Changed classes to manage certificates with polymorphism and base:derived
* Added Tor's Ed25519 certificate managing class
* More CERTS cell validations done

## 2021-04-18
* Added more commands for debugging and normal use
* RSA certificates validation is ready (using ESP32 mbedtls library)
* First cells exchange with Guard node working!!
* Added a smart (but will do better) method to get needed relays
* TLS connection working
* Added class to manage cells, circuit, relay, certificates, general networking
* Added NTP time sync at ESP32 boot
* Encrypted AES128 config file working (SPIFFS filesystem)
* Memory checks are OK!

## 2021-04-18
At the moment just a non-working draft!
