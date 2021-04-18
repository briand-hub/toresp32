# toresp32
Briand's project to turn an ESP32 into a Tor client "plug&amp;play"

## Development status
04/2021 At the moment just a non-working draft!
For news check always [NEWS FILE](NEWS)

## Intro
This project borns just for personal interest on ESP32 platform (I'm using WeMos LolinD32 v.1.0.0) because it summarize my interests for electronics, programming, c++ and cryptography. I think [Tor](https://www.torproject.org/) is a great example of applied cryptography for a noble purpose. 
Unfortunatley Tor has little or no library and the protocol specifications/documentation is very poor. Seems also that implementations (found just two, written in C and Python) are a bit complicated to decode and catch Tor's "secrets" and moreover code is not organized in my own "way". So I decided to start this project.

## The goal
The goal is to write a very simple C++17 working Tor client for ESP32 that prints the output on the serial port buffer with in a formatted way so the ESP32 could be attached to any computer with a bash/dos/putty client ready-to-go. The output format *should* allow the parsing for any other program that would consume this output.
The next step would be using ESP32's AP interface to give a sort of SOCKS5 protocol for use with any browser (this of course at own risk).
The serial output leak might occour so any file (configuration) and the serial buffer itself could be encrypted using AES.

## Usage disclamer and license
This code is open source and protected by GPL v3 license, see [LICENSE FILE](LICENSE).
This project is intended **only** for educational purposes and any modification, unintended use, illegal use is *your own* responsibility.
This project has no warranty in any sense.

## The code
It is written in C++17. The project is a PlatformIO project based on WEMOS LOLIN D32 platform. The framework used is Arduino.
In order to enable C++17 support platformio.ini file has been edited adding reference to the last dev release of arduino-esp32 (currently using EspressIf IDF 4.4). Also the toolchain xtensa32 is upgraded to support gnu++17 keyword.
I would like to keep the code well-organized and as simple as possible. I'll try to add all the documentation and useful comments where necessary.
The code will implement the **current** last specifications and will not support any deprecated or *will-be-deprecated* (imho) feature. For example if I have to choose to implement hidden services, I would just write code for V3 and not any previous version (sorry, I have no time).

## Dev environment
Project is built with VSCode and PlatformIO on WEMOS LOLIND32 platform and Arduino framework.

## Challenges

1. Implement a Tor protocol with just 512KB SRAM and 4MB flash space
2. Learn-by-doing Tor protocol
3. Find the time for this project :-/

## Task list

- [x] Create base project
- [x] First project commit
- [x] Add MAC Change function
- [x] Support for simple filesystem (SPIFFS or LittleFS)
- [x] Connection parameters could be saved in a configuration file (encrypted with 16 char password / AES-128)
- [x] Add a vintage logo :-)
- [ ] Study TOR protocol
- [ ] ...

## Future ideas
* Add a TRNG (true random number generator) with a Zener diode 
* Enable AP interface for SOCKS connections instead of serial buffer
* Implement Hidden Services 
