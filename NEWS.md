# Development status

## Next steps

* Write certificate validation methods
* Simplify code
* Prepare stub method to authenticate client
* Send NETINFO cell after CERTS cell authentication
* Authenticate cell?

## ?

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
