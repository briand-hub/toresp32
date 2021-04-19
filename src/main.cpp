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

// Warning: all frameworks libs must be called there
// otherwise Platformio errors are thrown
// other way: add it to lib_deps in platformio.ini file

/* Framework libraries */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <FS.h>
#include <SPIFFS.h>
#include <WiFiClientSecure.h>

/* Standard C++ libraries */
#include <iostream>
#include <memory>
#include <climits>

/* Platformio libraries */
#include <ArduinoJson.h>
#include "time.h"

/* Project libraries */
#include "BriandTorEsp32Config.hxx"
#include "BriandTorAes.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorCircuit.hxx"

using namespace std;

/* Global parameters (change it if you want by editing global file) */
#include "BriandDefines.hxx"

/* Global declarations */
unsigned short nextStep = 0;
bool SERIAL_INPUT_READING = false;
string* SERIAL_INPUT_POINTER = nullptr;
unique_ptr<string> CONFIG_PASSWORD = nullptr;
unique_ptr<string> SERIAL_ENC_KEY = nullptr;
unique_ptr<string> STA_ESSID = nullptr;
unique_ptr<string> STA_PASSW = nullptr;
unique_ptr<string> AP_ESSID = nullptr;
unique_ptr<string> AP_PASSW = nullptr;
unique_ptr<string> COMMAND = nullptr;
unsigned long long int COMMANDID = 0;

/* Early declarations */
void reboot();
void printLocalTime();
void printLogo();
void startSerialRead(string*);
void executeCommand(string&);

/* Setup: executed once at boot */
void setup() {
    // Initialize globals
    CONFIG_PASSWORD = make_unique<string>("");
    SERIAL_ENC_KEY = make_unique<string>("");
    STA_ESSID = make_unique<string>("");
    STA_PASSW = make_unique<string>("");
    AP_ESSID = make_unique<string>("");
    AP_PASSW = make_unique<string>("");
    COMMAND = make_unique<string>("");
    COMMANDID = 0;

    // Begin serial communication
    Serial.begin(SERIAL_BAUD_RATE);
    Serial.setRxBufferSize(1);
	Serial.println("");

    if (VERBOSE) Serial.printf("Entering step %d\n", nextStep);

    // Turn off leds
	if (VERBOSE) Serial.printf("Turning OFF built led %d\n", LED_BUILTIN);
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, 1); // 1 => off, 0 => on

	// Set time to UTC 

	if (VERBOSE) {
		//
		// TODO
		//

		// Maybe not necessary? RTC is resetting...
	}

    if (VERBOSE) {
        // Execute tests
        Serial.printf("[TEST] UULONG MAX VALUE (hex): 0x%016llx\n", ULLONG_MAX);

        // Check Filesystem
        if (!SPIFFS.begin(true))
            Serial.println("[TEST] Filesystem SPIFFS error.");
        else 
            Serial.println("[TEST] Filesystem SPIFFS OK.");

		// Test ArduinoCrypto suite for what needed


        // Test AES configuration encryption suite (MbedTLS suite)
        string test = "Hello from an {AES128} configuration file.";
        string key = "1234567890123456";
        int t = 0;
        auto config = make_unique<Briand::BriandTorEsp32Config>(key);
        Serial.printf("[TEST] AES Encryption test, string <%s>\n", test.c_str());
        auto buf = config->encrypt(test);
        Serial.print("[TEST] Encrypted Bytes: ");
        for (int i = 0; i<test.length(); i++)
           Serial.printf("%0x ", buf.get()[i] );
        Serial.printf("\n[TEST] Decrypted Bytes: <%s>\n", config->decrypt(buf, test.length()).c_str());
        Serial.println("[TEST] AES Test success.");
    }

	// Init WiFi to AP+STA 

	if (VERBOSE) Serial.println("Initializing WiFi\n");
	WiFi.mode(WIFI_MODE_APSTA);

    // Change MAC address to a random one
    if (CHANGE_MAC_TO_RANDOM) {
        auto nmacAP = Briand::BriandUtils::GetRandomMAC();
        auto nmacSTA = Briand::BriandUtils::GetRandomMAC();

        if (VERBOSE) { 
			// Note: ESP32 seems does not change mac if the first byte does not 
			// fit the base mac. See comments:
			// https://randomnerdtutorials.com/get-change-esp32-esp8266-mac-address-arduino/

			uint8_t baseMac[6];
			esp_base_mac_addr_get(baseMac);
			nmacAP[0] = baseMac[0];
			nmacSTA[0] = baseMac[0];

			Serial.printf("Current baseMAC: %02x:%02x:%02x:%02x:%02x:%02x\n", baseMac[0], baseMac[1], baseMac[2], baseMac[3], baseMac[4], baseMac[5]);
            Serial.printf("Current AP  MAC: %s\n", WiFi.softAPmacAddress().c_str());
            Serial.printf("Current STA MAC: %s\n", WiFi.macAddress().c_str());
			Serial.println("");
			Serial.printf("Change   AP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", nmacAP[0], nmacAP[1], nmacAP[2], nmacAP[3], nmacAP[4], nmacAP[5]);
            Serial.printf("Change  STA MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", nmacSTA[0], nmacSTA[1], nmacSTA[2], nmacSTA[3], nmacSTA[4], nmacSTA[5]);
        }

        auto errAp = esp_wifi_set_mac(WIFI_IF_AP, nmacAP.get());
		if (errAp != ESP_OK) Serial.printf("[ERR] Error on changing AP mac address: %s\n", esp_err_to_name(errAp));
        auto errSta =  esp_wifi_set_mac(WIFI_IF_STA, nmacSTA.get());
		if (errSta != ESP_OK) Serial.printf("[ERR] Error on changing STA mac address: %s\n", esp_err_to_name(errSta));

        if (VERBOSE) { 
			Serial.println("");
            Serial.printf("****New AP  MAC: %s\n", WiFi.softAPmacAddress().c_str());
            Serial.printf("****New STA MAC: %s\n", WiFi.macAddress().c_str());
        }
    }

	// Init STA and AP with random hostname

	auto staHostname = Briand::BriandUtils::GetRandomHostName();
	auto apHostname = Briand::BriandUtils::GetRandomHostName();
	
	if (WiFi.setHostname(staHostname.get())) {
		Serial.printf("STA WiFi hostname is: %s\n", WiFi.getHostname());
	}
	else {
		Serial.printf("[ERR] Error on setting STA hostname, will remain: %s\n", WiFi.getHostname());
	}

	if (WiFi.softAPsetHostname(apHostname.get())) {
		Serial.printf("AP WiFi hostname is: %s\n", WiFi.softAPgetHostname());
	}
	else {
		Serial.printf("[ERR] Error on setting AP hostname, will remain: %s\n", WiFi.softAPgetHostname());
	}
	
    // Print welcome
    printLogo();

    Serial.println("Serial communication: press [ENTER] to confirm inputs/commands. BACKSPACE *MAY* not work!\n\n");

    nextStep = 1; // setup success
}


/* Loop: executed repeatedly */
void loop() {
    // If during serial input reading, wait while the command is entered and confirmed.
    if (SERIAL_INPUT_READING) {
        if (Serial.available() > 0) {
            char in = Serial.read();
            if (in != 13 && in != 10 && in > 0) {
                // Backspace handling
                if (in == 8 && SERIAL_INPUT_POINTER->length() > 0) {
                    SERIAL_INPUT_POINTER->resize(SERIAL_INPUT_POINTER->length() - 1);
					// To "show" backspace print backspace, then a space and a new backspace
                    Serial.print(in);
					Serial.print(" ");
					Serial.print(in);
                }
                else if (in != 8) {
                    SERIAL_INPUT_POINTER->push_back(in);
                    Serial.print(in);
                }
            }
            else if (in == 13) {
                SERIAL_INPUT_READING = false;
                SERIAL_INPUT_POINTER = nullptr;
                // Trim any \r 
                //SERIAL_INPUT_POINTER->erase( SERIAL_INPUT_POINTER-> )
            }
            return;
        }
    }
    // ---------------------------------------------------------------------------------
    else if (nextStep == 1) {
        // Setup done, check if there is any saved configuration.
        // If so, ask user the password to decrypt, if no password given then delete old configuration and ask for new
        if (Briand::BriandTorEsp32Config::existConfig()) {
            Serial.printf("Configuration file found. Enter Password to use or [Enter] to skip: ");
            startSerialRead(CONFIG_PASSWORD.get());
            nextStep = 2;
        }
        else {
            // If not, go to step 3 and ask for essid
            nextStep = 3;
        }
    }
    else if (nextStep == 2) {
        // User password for config decrypt has been read.
        auto cfg = make_unique<Briand::BriandTorEsp32Config>( *CONFIG_PASSWORD.get() );
        if (CONFIG_PASSWORD->length() >= 16) {
            CONFIG_PASSWORD->resize(16);

            if (!cfg->readConfig()) {
                // Not valid, destroy and re-do
                Serial.println("\n[WARN] Configuration is not valid! Has been destroyed forever!");
                cfg->destroyConfig();
                CONFIG_PASSWORD->clear();

                nextStep = 3; // ask for essid
            }
            else {
                STA_ESSID->append(cfg->WESSID);
                STA_PASSW->append(cfg->WPASSWORD);
                VERBOSE = cfg->VERBOSE;
                SERIAL_ENC_KEY->append(cfg->SERIAL_ENC_KEY);

                // If a serial encoding key is set, use crypt.

                // TODO !

                // go to connect
                nextStep = 6;
            }
        }
        else {
            Serial.println("\n[WARN] Password not given or less than 16 chars.");
            cfg->destroyConfig();            
            Serial.println("[WARN] Configuration has been destroyed forever!");
            CONFIG_PASSWORD->clear();

            nextStep = 3; // ask for essid
        }
    }
    else if (nextStep == 3) {
        // Step 3 => Ask for Essid
        Serial.print("Connect to WiFi - ESSID: ");
        nextStep = 4;
        startSerialRead(STA_ESSID.get());
    }
    else if (nextStep == 4) {
        // Got Essid, ask for password
        if (DEBUG) Serial.printf("  >Entered: %s\n", STA_ESSID->c_str());
        Serial.print("Connect to WiFi - PASSWORD: ");
        nextStep = 5;
        startSerialRead(STA_PASSW.get());
    }
    else if (nextStep == 5) {
        // Got Password, connect
        if (DEBUG) Serial.printf("  >Entered: %s\n", STA_PASSW->c_str());
        nextStep = 6;
    }
    else if (nextStep == 6) {
        // Connect station, until timeout reached.
        unsigned long int timeout = millis() + WIFI_CONNECTION_TIMEOUT*1000;
        Serial.printf("Connecting to %s", STA_ESSID->c_str());

        WiFi.begin(STA_ESSID->c_str(), STA_PASSW->c_str());
        while (!WiFi.isConnected() && millis() < timeout) {
            delay(1000);
            if (VERBOSE) Serial.print(".");
        }

        Serial.println("");

        if (!WiFi.isConnected()) {
            Serial.println("\n\nWIFI CONNECTION ERROR/TIMEOUT. SYSTEM WILL RESTART IN 5 SECONDS!");
            delay(5*1000);
            reboot();
        }

        Serial.println("connected!");
        if (VERBOSE) Serial.printf("LAN IP Address: %s\n", WiFi.localIP().toString().c_str());
        delay(500);

        nextStep = 7;
    }
    else if (nextStep == 7) {
        // Ask user if would save config. In this case password must be given. If not, skip save.
        // This of course if not saved before...

        if (CONFIG_PASSWORD->length() == 0) {
            Serial.print("Would you like to save config? Enter a password ([Enter] to skip): ");
            startSerialRead(CONFIG_PASSWORD.get());
        }
        nextStep = 8;
    }
    else if (nextStep == 8) {
        // User has given (or not) the password to encrypt config
        if (CONFIG_PASSWORD->length() >= 16) {
            // Encrypt & save
            CONFIG_PASSWORD->resize(16);
            auto cfg = make_unique<Briand::BriandTorEsp32Config>( *CONFIG_PASSWORD.get() );
            cfg->WESSID.append( STA_ESSID->c_str() );
            cfg->WPASSWORD.append(STA_PASSW->c_str());
            cfg->SERIAL_ENC_KEY.append(SERIAL_ENC_KEY->c_str());
            cfg->VERBOSE = VERBOSE;
            cfg->writeConfig();
            Serial.println("\nConfiguration file written!");
        }
		else {
			Serial.println("\nPassword must be 16 chars! Configuration file NOT written!");
		}

        // Now cleanup not anymore needed infos
        CONFIG_PASSWORD.reset();
        STA_ESSID.reset();
        STA_PASSW.reset();

		// Initialize AP interface

		if(VERBOSE) Serial.println("Now initializing AP interface...");

		auto apEssid = Briand::BriandUtils::GetRandomSSID();
		auto apPassword = Briand::BriandUtils::GetRandomPassword(WIFI_AP_PASSWORD_LEN);
		if (WiFi.softAP(apEssid.get(), apPassword.get(), WIFI_AP_CH, WIFI_AP_HIDDEN, WIFI_AP_MAX_CONN)) {
			if(VERBOSE) Serial.printf("AP Ready. ESSID: %s PASSWORD: %s\n", apEssid.get(), apPassword.get());
			AP_ESSID = make_unique<string>( apEssid.get() );
			AP_PASSW = make_unique<string>( apPassword.get() );
			
			//
			// TODO: add a handler for AP commands
			//



		}
		else {
			Serial.println("[ERR] Error on AP init! Only serial communication is enabled.");
		}

        // Proceed to next step
        nextStep = 9;
    }
    else if (nextStep == 9) {

        if (VERBOSE) printLocalTime();
        if (VERBOSE) Serial.println("Sync time to UTC+0 (no daylight saving) with NTP");

        //For UTC -5.00 : -5 * 60 * 60 : -18000
        //For UTC +1.00 : 1 * 60 * 60 : 3600
        //For UTC +0.00 : 0 * 60 * 60 : 0
        const long  gmtOffset_sec = 0;

        // to 3600 if daylight saving
        const int daylightOffset_sec = 0; 

        // init and get the time
        configTime(gmtOffset_sec, daylightOffset_sec, NTP_SERVER);

        if (VERBOSE) printLocalTime();

        // Proceed to next steps
        nextStep = 100;
    }
    else if (nextStep == 100) {
        Serial.println("Creating TOR circuits");
        
        // ... todo

        nextStep = 900;

        Serial.println("\n\nSYSTEM READY! Type help for commands.\n");
    }
    else if (nextStep == 900) {
        // Here system ready for commands
        Serial.print("briand toresp32 > ");
        startSerialRead(COMMAND.get());
        nextStep = 901;
    }
    else if (nextStep == 901) {
        // Command received
        // Execute.....
        executeCommand( *(COMMAND.get()) );

        // Wait for next command
        nextStep = 900;
    }
}

/* Support functions */

void printLogo() {
	// Logo created with https://patorjk.com/software/taag/#p=display&f=Doom&t=TorEsp32
    Serial.println("\n\n\n");
    Serial.println(" _____            _____           _____  _____ ");
    Serial.println("|_   _|          |  ___|         |____ |/ __  \\");
    Serial.println("  | | ___  _ __  | |__ ___ _ __      / /`' / /'");
    Serial.println("  | |/ _ \\| '__| |  __/ __| '_ \\     \\ \\  / /  ");
    Serial.println("  | | (_) | |    | |__\\__ \\ |_) |.___/ /./ /___");
    Serial.println("  \\_/\\___/|_|    \\____/___/ .__/ \\____/ \\_____/");
    Serial.println("                          | |                  ");
    Serial.println("                          |_|                  ");
    Serial.println("                                               ");
    Serial.println("                VERSION 1.0.0                  ");
    Serial.println("              (Pandemic edition)               ");
    Serial.println("          Copyright (C) 2021 briand            ");
    Serial.println("        https://github.com/briand-hub          ");
    Serial.println("                                               ");
}

void printLocalTime()
{
    struct tm timeinfo;
    if(!getLocalTime(&timeinfo)){
        Serial.println("Failed to obtain time");
        return;
    }
    Serial.println(&timeinfo, "Local time: %A, %B %d %Y %H:%M:%S");
}

void reboot() {
    // Cleanup
    WiFi.disconnect(true, true);

    // FS dismount
    SPIFFS.end();

    // Serial stop
    Serial.flush();
    Serial.end();
    
    // Restart
    esp_restart();
}

void startSerialRead(string* sPtr) {
    SERIAL_INPUT_POINTER = sPtr;
    SERIAL_INPUT_READING = true;
}

void executeCommand(string& cmd) {
	// Get heap size before command
	unsigned long int heapBefore = ESP.getFreeHeap();

    // Assign a command ID for external processing (will reset after max value for long tasks)
    if ( COMMANDID == ULLONG_MAX)
        COMMANDID = 0;
    else 
        COMMANDID++;

    Serial.printf("\n[CMD][0x%016llx]: %s\n", COMMANDID, cmd.c_str());
    Serial.printf("[EXE][0x%016llx]\n", COMMANDID);

	if (cmd.compare("help") == 0) {
        Serial.println("COMMAND : description");
		Serial.println("GENERAL-------------------------------------------------------------------");
		Serial.println("help : display this.");
        Serial.println("time : display date and time.");
		Serial.println("devinfo : display device information.");
		Serial.println("meminfo : display short memory information.");
		Serial.println("netinfo : display network STA/AP interfaces information.");
		Serial.println("apoff : turn off AP interface.");
		Serial.println("apon : turn on AP interface (will keep intact hostname/essid/password).");
		Serial.println("reboot : restart device.");

		if (DEBUG) {
			Serial.println("TOR TESTING (DEBUG ACTIVE)------------------------------------------------");
			Serial.println("search-guard : if DEBUG active, search and display info for a guard node.");
			Serial.println("search-exit : if DEBUG active, search and display info for an exit node.");
			Serial.println("search-middle : if DEBUG active, search and display info for a middle node.");
			Serial.println("testcircuit : if DEBUG active, build a new circuit just for testing.");
		}

		Serial.println("TOR TESTING------------------------------------------------------------------");
		Serial.println("ifconfig.me : Show ifconfig.me information (NON-TOR REQUEST, REAL ADDRESS).");
    }
    else if (cmd.compare("time") == 0) {
        printLocalTime();
    }
    else if (cmd.compare("devinfo") == 0) {
        Serial.printf("CPU Frequency: %uMHz\n", ESP.getCpuFreqMHz());
        Serial.printf("Heap size: %u bytes\n", ESP.getHeapSize());
        Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
        Serial.printf("Max. allocated heap: %u bytes\n", ESP.getMaxAllocHeap());
		Serial.printf("PSram size: %u bytes\n", ESP.getPsramSize());
        Serial.printf("Free PSram: %u bytes\n", ESP.getFreePsram());
		Serial.printf("Max. allocated PSram: %u bytes\n", ESP.getMaxAllocPsram());
        Serial.printf("File system size: %u bytes\n", SPIFFS.totalBytes());
        Serial.printf("File system used: %u bytes\n", SPIFFS.usedBytes());
        Serial.printf("File system free: %u bytes\n", (SPIFFS.totalBytes()-SPIFFS.usedBytes()));
    }
	else if (cmd.compare("meminfo") == 0) {
        Serial.printf("HEAP FREE: %u / %u bytes. PSRAM FREE: %u / %u bytes. FS: %u / %u bytes.\n", ESP.getFreeHeap(), ESP.getHeapSize(), ESP.getFreePsram(), ESP.getPsramSize(), (SPIFFS.totalBytes()-SPIFFS.usedBytes()), SPIFFS.totalBytes());
    }
	else if (cmd.compare("netinfo") == 0) {
        Serial.printf("AP Hostname: %s\n", WiFi.softAPgetHostname());
		Serial.printf("AP MAC: %s\n", WiFi.softAPmacAddress().c_str());
		Serial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
		Serial.printf("AP SSID: %s\n", AP_ESSID->c_str());
		Serial.printf("AP Password: %s\n", AP_PASSW->c_str());
        Serial.printf("STA Hostname: %s\n", WiFi.getHostname());
        Serial.printf("STA MAC: %s\n", WiFi.macAddress().c_str());
        Serial.printf("STA IPv4: %s\n", WiFi.localIP().toString().c_str());
		Serial.printf("STA IPv6: %s\n", WiFi.localIPv6().toString().c_str());
		Serial.printf("STA GW: %s\n", WiFi.gatewayIP().toString().c_str());
    }
	else if (cmd.compare("reboot") == 0)  {
        Serial.println("Device will reboot now.");
		reboot();
    }
	else if (cmd.compare("apoff") == 0)  {
		if (WiFi.softAPdisconnect() && WiFi.mode(WIFI_STA)) Serial.println("AP has been turned off.");
		else Serial.println("[ERR] Error turning off AP.");
    }
	else if (cmd.compare("apon") == 0)  {
		if (WiFi.mode(WIFI_MODE_APSTA) && WiFi.softAP(AP_ESSID->c_str(), AP_PASSW->c_str(), WIFI_AP_CH, WIFI_AP_HIDDEN, WIFI_AP_MAX_CONN)) {
			if(VERBOSE) Serial.printf("AP Ready. ESSID: %s PASSWORD: %s\n", AP_ESSID->c_str(), AP_PASSW->c_str());
		}
		else {
			Serial.println("[ERR] Error on AP init! Only serial communication is enabled.");
		}
    }
	else if (cmd.compare("search-guard") == 0 && DEBUG)  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetGuardRelay();
		
		if (relay != nullptr)
			Serial.println("SUCCESS");
		else 
			Serial.println("FAILED");
    }
	else if (cmd.compare("search-exit") == 0 && DEBUG)  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetExitRelay();
		
		if (relay != nullptr)
			Serial.println("SUCCESS");
		else 
			Serial.println("FAILED");
    }
	else if (cmd.compare("search-middle") == 0 && DEBUG)  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetMiddleRelay();
		
		if (relay != nullptr)
			Serial.println("SUCCESS");
		else 
			Serial.println("FAILED");
    }
	else if (cmd.compare("testcircuit") == 0 && DEBUG)  {
		auto tempCircuit = make_unique<Briand::BriandTorCircuit>();
		
		if (tempCircuit->BuildCircuit()) {
			Serial.println("SUCCESS! Cuircuit built:");
			Serial.printf("You <----> G[%s] <----> M[%s] <----> E[%s] <----> Web\n", tempCircuit->guardNode->nickname->c_str(), tempCircuit->middleNode->nickname->c_str(), tempCircuit->exitNode->nickname->c_str());
		}
		else 
			Serial.println("FAILED to build a circuit.");
    }
	else if (cmd.compare("ifconfig.me") == 0)  {
		string info = Briand::BriandUtils::BriandIfConfigMe();
		Serial.printf("\nInfo about your real identity:\n\n%s\n", info.c_str());
    }
	
	// other commands implementation...
    else {
        Serial.printf("Unknown command.\n");
    }

    Serial.printf("[EXE][0x%016llx][END]\n", COMMANDID);

	// Debug: print memory used by command
	if (DEBUG) Serial.printf("[DEBUG] Heap consumption: %lu (from %lu to %lu) bytes.", (heapBefore - ESP.getFreeHeap()), heapBefore, ESP.getFreeHeap());

    // Clear COMMAND for next
    COMMAND->clear();
}

