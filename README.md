# toresp32
Briand's project to turn an ESP32 into a Tor client "plug&amp;play"

## Development status

For details check always [NEWS FILE](NEWS.md)

* Working to a faster/better proxy (version 1.1.0)

**FIRST RELEASE AVAILABLE [go to release](https://github.com/briand-hub/toresp32/releases/tag/v1.0.0)**

* 08/2021 Ready to release
* 08/2021 Proxy working through Tor for HTTP/HTTPS requests!
* 07/2021 With updated [library](https://www.github.com/briand-hub/LibBriandIDF) and small modifications now this project can work both on ESP32 and Linux systems (see details below)
* 07/2021 Working with multiple circuits (managed asynchronously): connection, hostname resolution
* 05/2021 Switching to IDF Framework completed and obtained the first working circuit!
* 04/2021 At the moment just a non-working draft!

## Intro
This project borns just for personal interest on ESP32 platform (I'm using WeMos LolinD32 v.1.0.0) because it summarize my interests for electronics, programming, c++ and cryptography. I think [Tor](https://www.torproject.org/) is a great example of applied cryptography for a noble purpose. 
Unfortunatley Tor has little or no library and the protocol specifications/documentation is very poor. Seems also that implementations (found just two, written in C and Python) are a bit complicated to decode and catch Tor's "secrets" and moreover code is not organized in my own "way". So I decided to start this project.

## The goal
The goal is to write a very simple C++17 working Tor proxy for ESP32 so the ESP32 could be attached to any computer with a bash/dos/putty client ready-to-go.
Using ESP as a proxy allows to keep no traces of Tor client/browser on your computer (but traces of the navigation history and so on **are not** avoided!).

## Usage disclaimer and license
This code is open source and protected by GPL v3 license, see [LICENSE FILE](LICENSE).
This project is intended **only** for educational purposes and any modification, unintended use, illegal use is *your own* responsibility.
This project has no warranty in any sense.

## Usage instructions

See [WIKI](https://github.com/briand-hub/toresp32/wiki).

**REMEMBER**: ESP32 is a 240MHz processor with 320KB of RAM. Do not expect good performances or fast webpage loading!!

## The code
It is written in C++17. The project is a PlatformIO project based on WEMOS LOLIN D32 platform. The framework used is Espressif IDF 4.4.
In order to enable C++17 support platformio.ini file has been edited adding reference to the last dev release of toolchain xtensa32 is upgraded to support gnu++17 keyword. Using C++17 also requires .vscode/c_cpp_properties.json edited (see platformio.ini file for specifications).
I would like to keep the code well-organized and as simple as possible. I'll try to add all the documentation and useful comments where necessary.
The code will implement the **current** last specifications and will not support any deprecated or *will-be-deprecated* (imho) feature. For example if I have to choose to implement hidden services, I would just write code for V3 and not any previous version (sorry, I have no time).

## Dev environment
Project is built with VSCode and PlatformIO on WEMOS LOLIND32 platform and Espressif IDF 4.3 framework.

## Linux Porting

Debugging and testing in ESP32 could be a very hard task. So I defined the needed IDF functions to my base [library](https://www.github.com/briand-hub/LibBriandIDF) and made the project easy to compile and debug on Linux systems (Using Debian 10.0 Buster)

### Requirements

* gcc/g++ with version greater than 8.4 
* MbedTLS Library (*sudo apt install libmbedtls-dev*)
* Sodium Library (*sudo apt install libsodium-dev*)
* LibBriandIDF (see below)

## Building project

### ESP32 Environment: PlatformIO and VSCode

Simply open the project with PlatformIO in VSCode, then use Build or Upload and Monitor menu. The required libraries should be automatically downloaded and installed.

### Linux Environment

First, clone the repo:

```bash
$ git clone https://github.com/briand-hub/toresp32
```

Install required libraries and switch the path to project root:

```bash
$ sudo apt install libsodium-dev libmbedtls-dev
$ cd toresp32
```

Then just clone the LibBriandIDF repo in the default path, like PlatformIO would do:

```bash
toresp32$ mkdir .pio
toresp32$ mkdir .pio/libdeps
toresp32$ mkdir .pio/libdeps/lolin_d32
toresp32$ cd .pio/libdeps/lolin_d32
toresp32/.pio/libdeps/lolin_d32$ git clone https://github.com/briand-hub/LibBriandIDF
```

Ready to build, use:

```bash
toresp32$ make
```

To execute:

```bash
toresp32$ ./main_linux_exe
```

To debug with valgrind:

```bash
toresp32$ sudo apt install valgrind
toresp32$ make
toresp32$ valgrind ./main_linux_exe
```

## Challenges

1. Implement a Tor protocol with just 320KB SRAM and 4MB flash space
2. Learn-by-doing Tor protocol
3. Find the time for this project :-/

## Task list

- [x] Create base project
- [x] First project commit
- [x] Add MAC Change function
- [x] Support for simple filesystem (SPIFFS or LittleFS)
- [x] Connection parameters could be saved in a configuration file (encrypted with 16 char password / AES-128)
- [x] Add a vintage logo :-)
- [x] Study TOR protocol
- [x] Working release

## Future ideas
* Add a TRNG (true random number generator) with a Zener diode 
* Implement Hidden Services 
