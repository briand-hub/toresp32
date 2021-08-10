# Development status

## Next steps

* Implement SENDME windows and cells
* Consider error management short/int for method errors (mbedtls style)
* Consider adding TIMEOUT seconds to Stream methods.
* Implement a vector of nodes.
* Change the "old" buffer-copy to vector->data() to optimize memory usage
* Simplify code in TorCircuit class
* Authenticate cell? => Prepare stub method to authenticate client

## 2021-08-08

* Need to change a little Socks5Proxy not catching client disconnect for http request and keeping socket opened. (main thread + one thread per accept())
* Removed COMMANDID and leak testing, switching to full socks5 proxy
* Moving to another cache implementation using microdescriptors from Authorities
* Added heap monitor to meminfo command
* Moved to microdescriptor cache and more efficient FetchDescriptorsFromAuthorities with readLine method of LibBriandIDF

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
