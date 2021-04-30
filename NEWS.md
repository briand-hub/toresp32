# Development status

## Next steps
* Add last_working_directory auth as static
* Find a way to get a small-size official consensus from directories (and remove ArduinoJson library)
* Simplify code in TorCircuit class
* Authenticate cell? => Prepare stub method to authenticate client

## 
* Key exchange was wrong, doing corrections
* Rename CertificateUtils class to CryptoUtils class

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
