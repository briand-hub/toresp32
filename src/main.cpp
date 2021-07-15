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

/* Framework libraries */
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_int_wdt.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <driver/gpio.h>
#include <esp_spiffs.h>
#include <esp_sntp.h>
#include <esp_timer.h>

/* Standard C++ libraries */
#include <iostream>
#include <memory>
#include <climits>
#include <time.h>

/* Custom specific libraries */
#include <BriandESPDevice.hxx>
#include <BriandIDFWifiManager.hxx>
#include <BriandIDFSocketClient.hxx>
#include <BriandIDFSocketTlsClient.hxx>

/* Project libraries */
#include "BriandTorEsp32Config.hxx"
#include "BriandTorAes.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorCircuit.hxx"
#include "BriandTorCryptoUtils.hxx"

/* Startup tests */

using namespace std;

/* Global parameters (change it if you want by editing global file) */
#include "BriandDefines.hxx"

// Required for C++ use WITH IDF!
extern "C" {
	void app_main();
}

/* Global declarations */
Briand::BriandIDFWifiManager* WiFi;
unsigned short nextStep = 0;
bool SERIAL_INPUT_READING = false;
string* SERIAL_INPUT_POINTER = nullptr;
unique_ptr<string> CONFIG_PASSWORD = nullptr;
unique_ptr<string> SERIAL_ENC_KEY = nullptr;
unique_ptr<string> AP_HOSTNAME = nullptr;
unique_ptr<string> STA_HOSTNAME = nullptr;
unique_ptr<string> STA_ESSID = nullptr;
unique_ptr<string> STA_PASSW = nullptr;
unique_ptr<string> AP_ESSID = nullptr;
unique_ptr<string> AP_PASSW = nullptr;
unique_ptr<string> COMMAND = nullptr;
unsigned long long int COMMANDID = 0;
unsigned int HEAP_LEAK_CHECK = 0;

/* Early declarations */
void reboot();
void syncTimeWithNTP();
void printLocalTime();
void printLogo();
void startSerialRead(string*);
void executeCommand(string&);

// Early declarations for setup/application
void TorEsp32Setup();
void TorEsp32Main(void*);

// MAIN METHOD
void app_main() {
	// Call setup
	TorEsp32Setup();

	// Start application loop
	xTaskCreate(TorEsp32Main, "TorEsp32", 8192, NULL, 5, NULL);
	// TODO: verify stack size
}

void TorEsp32Setup() {
	// Initialize globals
    CONFIG_PASSWORD = make_unique<string>("");
    SERIAL_ENC_KEY = make_unique<string>("");
	AP_HOSTNAME = make_unique<string>("");
	STA_HOSTNAME = make_unique<string>("");
    STA_ESSID = make_unique<string>("");
    STA_PASSW = make_unique<string>("");
    AP_ESSID = make_unique<string>("");
    AP_PASSW = make_unique<string>("");
    COMMAND = make_unique<string>("");
    COMMANDID = 0;

	// Common for error testing
	esp_err_t ret;

	// Initialize the NVS
	if (VERBOSE) printf("[INFO] Initializing NVS...");
	ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);
	if (VERBOSE) printf("done.\n");

    // De-buffered serial communication
	if (VERBOSE) printf("[INFO] Unbuffering stdout...");
	setvbuf(stdout, NULL, _IONBF, 0);
	if (VERBOSE) printf("done.\n");
	if (VERBOSE) printf("[INFO] Unbuffering stdin...");
	setvbuf(stdin, NULL, _IONBF, 0);
	if (VERBOSE) printf("done.\n");

    if (VERBOSE) printf("[INFO] Entering step %d\n", nextStep);

    // Turn off leds
	if (VERBOSE) printf("[INFO] Turning OFF built led %d\n", GPIO_NUM_5);
    gpio_set_direction(GPIO_NUM_5, GPIO_MODE_OUTPUT);
    gpio_set_level(GPIO_NUM_5, 1); // 1 => off, 0 => on
    
	// Initialize SPIFFS File System
	
	if (VERBOSE) printf("[INFO] Initializing SPIFFS file system...");
	
	esp_vfs_spiffs_conf_t conf = {
		.base_path = "/spiffs",
		.partition_label = NULL,
		.max_files = 5, // max concurrent opened files
		.format_if_mount_failed = true
	};
	
	// Use settings defined above to initialize and mount SPIFFS filesystem.
	// Note: esp_vfs_spiffs_register is an all-in-one convenience function.
	// (will format if not ready!)
	ret = esp_vfs_spiffs_register(&conf);

	if (ret != ESP_OK) {
		if (ret == ESP_FAIL) {
			if (VERBOSE) printf("FAILED! (mont error)\n");
		}
		else if (ret == ESP_ERR_NOT_FOUND) {
			if (VERBOSE) printf("FAILED! (failed to find SPIFFS partition)\n");
		}
		else {
			if (VERBOSE) printf("FAILED! reason: %s\n", esp_err_to_name(ret));
		}
		
		return; // Will create panic
	}

	if (VERBOSE) printf("done.\n");
	
	unsigned int total = 0, used = 0;
	ret = esp_spiffs_info(conf.partition_label, &total, &used);
	if (ret != ESP_OK) {
		if (VERBOSE) printf("[INFO] Failed to get SPIFFS partition information: %s\n", esp_err_to_name(ret));
	}	
	else {
		if (VERBOSE) printf("[INFO] Partition size: total: %d used: %d bytes.\n", total, used);
	} 

    if (VERBOSE) {
        // Benchmarking
        unsigned long testStart = 0;

        // Execute tests
        printf("[TEST] UULONG MAX VALUE (hex): 0x%016llx\n", ULLONG_MAX);

        // Test AES configuration encryption suite (MbedTLS suite)
        string test = "Hello from an {AES128} configuration file.";
        string key = "1234567890123456";
        auto config = make_unique<Briand::BriandTorEsp32Config>(key);
        printf("[TEST] AES Encryption test, string <%s> with key <%s>\n", test.c_str(), key.c_str());
        testStart = esp_timer_get_time();
        auto buf = config->Encrypt(test);
        printf("[TEST] Took %llu milliseconds.\n", (esp_timer_get_time() - testStart)/1000L);
        printf("[TEST] Encrypted Bytes: ");
		Briand::BriandUtils::PrintOldStyleByteBuffer(buf.get(), test.length(), test.length()+1, test.length());
        testStart = esp_timer_get_time();
        printf("[TEST] Decrypted Bytes: <%s>\n", config->Decrypt(buf, test.length()).c_str());
        printf("[TEST] Took %llu milliseconds.\n", (esp_timer_get_time() - testStart)/1000L);
        printf("[TEST] AES Test success.\n");
		buf.reset();
		config.reset();

		// Test SHA256
		string testMessage = string("546F7220544C53205253412F456432353531392063726F73732D63657274696669636174651EAE084E96C9150FAE941A28DD7A9B718EFD0F759D7021A9754A717C65D19B350006EA89");
		string expResult = string("457E063D5CE929FE98AF745D1DA20306422E9203298E69408F75B0595EA703C7");
		auto message = Briand::BriandUtils::HexStringToVector(testMessage, "");
		printf("[TEST] Perform SHA256 hash of:  %s\n", testMessage.c_str());
		printf("[TEST] Expected output:         %s\n", expResult.c_str());
        testStart = esp_timer_get_time();
		auto hash = Briand::BriandTorCryptoUtils::GetDigest_SHA256(message);
		printf("[TEST] Took %llu milliseconds.\n", (esp_timer_get_time() - testStart)/1000);
        printf("[TEST] SHA256 computed hash is: ");
		Briand::BriandUtils::PrintByteBuffer(*(hash.get()), hash->size()+1, hash->size());
		auto expResultV = Briand::BriandUtils::HexStringToVector(expResult, "");
		if (expResultV->size() != hash->size()) printf("[TEST] FAIL SHA256, sizes do not math (%d against expected %d).\n", hash->size(), expResultV->size());
		else {
			bool differentFound = false;
			for (int i=0; i<hash->size() && !differentFound; i++)
				differentFound = ( hash->at(i) != expResultV->at(i) );
			if (!differentFound) printf("[TEST] SHA256 test success!\n");
			else printf("[TEST] SHA256 test failure! (hash does not match expected result).\n");
		}
		message.reset();
		hash.reset();
		expResultV.reset();
    }

	// Init WiFi to AP+STA 
	
	if (VERBOSE) printf("[INFO] Initializing WiFi\n");

	WiFi = Briand::BriandIDFWifiManager::GetInstance();
	WiFi->SetVerbose(false, true);

	// Init STA and AP random hostnames

	STA_HOSTNAME->append( Briand::BriandUtils::GetRandomHostName().get() );
	AP_HOSTNAME->append( Briand::BriandUtils::GetRandomHostName().get() );
	
	// High processor frequency
	if (VERBOSE) printf("[INFO] Setting CPU speed to 240MHz\n");
	Briand::BriandESPDevice::SetCpuFreqMHz(240);
	if (VERBOSE) printf("[INFO] Current CPU speed is %lu MHz.\n", Briand::BriandESPDevice::GetCpuFreqMHz());

    // Print welcome
    printLogo();

    printf("[INFO] Serial communication: press [ENTER] to confirm inputs/commands. BACKSPACE *MAY* not work!\n\n\n");

    nextStep = 1; // setup success
}

void TorEsp32Main(void* taskArg) {
	// An xTask cannot return!
	while (1) {
		//
		// TODO
		//
		// In this place, if something is received/sent from serial or socks
		// or ap etc... handle it!
		// eg. circuit tear down request / new circuits to build etc.
		// this should be done only if all has been setup (nextStep >= 10000)
		//

		// If during serial input reading, wait while the command is entered and confirmed.
		if (SERIAL_INPUT_READING) {
			char in = (char)fgetc(stdin);
			if (in != 13 && in != 10 && in > 0 && in != 0xFF) {
				// Backspace handling
				if (in == 8 && SERIAL_INPUT_POINTER->length() > 0) {
					SERIAL_INPUT_POINTER->resize(SERIAL_INPUT_POINTER->length() - 1);
					// To "show" backspace print backspace, then a space and a new backspace
					printf("%c %c", in, in);
				}
				else if (in != 8) {
					SERIAL_INPUT_POINTER->push_back(in);
					printf("%c", in);
				}
			}
			else if (in == 13 || in == 10) {
				SERIAL_INPUT_READING = false;
				SERIAL_INPUT_POINTER = nullptr;

				// de-buffer (terminal "sticky" keys)
				while (in != 0xFF || in < 0) in = (char)fgetc(stdin);
			}

			// delay before next check
			vTaskDelay(20/portTICK_PERIOD_MS);
		}
		// ---------------------------------------------------------------------------------
		// STEPS: 
		//  SERIAL_INPUT_READING (only for reading serial commands)
		//  from      0 to   999 initial setup
		//  from  1.000 to 9.999 tor setup
		//  from 10.000 to ..... commands
		// ---------------------------------------------------------------------------------
		else if (nextStep == 1) {
			// Setup done, check if there is any saved configuration.
			// If so, ask user the password to decrypt, if no password given then delete old configuration and ask for new
			if (Briand::BriandTorEsp32Config::ExistConfig()) {
				printf("Configuration file found. Enter Password to use or [Enter] to skip: ");
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

				if (!cfg->ReadConfig()) {
					// Not valid, destroy and re-do
					printf("\n[WARN] Configuration is not valid! Has been destroyed forever!\n");
					cfg->DestroyConfig();
					CONFIG_PASSWORD->clear();

					nextStep = 3; // ask for essid
				}
				else {
					STA_ESSID->append(cfg->WESSID);
					STA_PASSW->append(cfg->WPASSWORD);
					SERIAL_ENC_KEY->append(cfg->SERIAL_ENC_KEY);

					// If a serial encoding key is set, use crypt.

					// TODO !

					// go to connect
					nextStep = 6;
				}
			}
			else {
				printf("\n[WARN] Password not given or less than 16 chars.\n");
				cfg->DestroyConfig();            
				printf("[WARN] Configuration has been destroyed forever!\n");
				CONFIG_PASSWORD->clear();

				nextStep = 3; // ask for essid
			}
		}
		else if (nextStep == 3) {
			// Step 3 => Ask for Essid
			printf("Connect to WiFi - ESSID: ");
			nextStep = 4;
			startSerialRead(STA_ESSID.get());
		}
		else if (nextStep == 4) {
			// Got Essid, ask for password
			if (DEBUG) printf("  >Entered: %s\n", STA_ESSID->c_str());
			printf("Connect to WiFi - PASSWORD: ");
			nextStep = 5;
			startSerialRead(STA_PASSW.get());
		}
		else if (nextStep == 5) {
			// Got Password, connect
			if (DEBUG) printf("  >Entered: %s\n", STA_PASSW->c_str());
			nextStep = 6;
		}
		else if (nextStep == 6) {
			// Connect station, until timeout reached.
			printf("[INFO] Connecting to %s ...", STA_ESSID->c_str());

			if (!WiFi->ConnectStation(*STA_ESSID.get(), *STA_PASSW.get(), WIFI_CONNECTION_TIMEOUT, *STA_HOSTNAME.get(), CHANGE_MAC_TO_RANDOM)) {
				printf("\n\n[ERR] WIFI CONNECTION ERROR/TIMEOUT. SYSTEM WILL RESTART IN 5 SECONDS!\n");
				vTaskDelay(5000 / portTICK_PERIOD_MS);
				reboot();
			}

			printf("connected!\n");

			if (VERBOSE) printf("[INFO] STA MAC: %s\n", WiFi->GetStaMAC().c_str());
			if (VERBOSE) printf("[INFO] LAN IP Address: %s\n", WiFi->GetStaIP().c_str());

			nextStep = 7;
		}
		else if (nextStep == 7) {
			// Ask user if would save config. In this case password must be given. If not, skip save.
			// This of course if not saved before...

			if (CONFIG_PASSWORD->length() == 0) {
				printf("Would you like to save config? Enter a password ([Enter] to skip): ");
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
				cfg->WriteConfig();
				printf("\n[INFO] Configuration file written!\n");
			}
			else {
				printf("\n[INFO] Password must be 16 chars! Configuration file NOT written!\n");
			}

			// Now cleanup not anymore needed infos
			CONFIG_PASSWORD.reset();
			STA_ESSID.reset();
			STA_PASSW.reset();

			// Initialize AP interface

			if(VERBOSE) printf("[INFO] Now initializing AP interface...\n");

			AP_ESSID = make_unique<string>(Briand::BriandUtils::GetRandomSSID().get());
			AP_PASSW = make_unique<string>(Briand::BriandUtils::GetRandomPassword(WIFI_AP_PASSWORD_LEN).get());
			//if (WiFi.softAP(apEssid.get(), apPassword.get(), WIFI_AP_CH, WIFI_AP_HIDDEN, WIFI_AP_MAX_CONN)) {
			if (WiFi->StartAP(*AP_ESSID.get(), *AP_PASSW.get(), WIFI_AP_CH, WIFI_AP_MAX_CONN, CHANGE_MAC_TO_RANDOM)) {
				if(VERBOSE) printf("[INFO] AP Ready. ESSID: %s PASSWORD: %s\n", AP_ESSID->c_str(), AP_PASSW->c_str());
				
				// Change default ip
				WiFi->SetApIPv4(10, 0, 0, 1);

				//
				// TODO: add a handler for AP commands
				//



			}
			else {
				printf("[ERR] Error on AP init! Only serial communication is enabled.\n");
			}

			// Proceed to next step
			nextStep = 9;
		}
		else if (nextStep == 9) {

			// Sync time with NTP (VERY IMPORTANT!)
			syncTimeWithNTP();

			// Proceed to next steps
			nextStep = 1000;
		}
		else if (nextStep == 1000) {
			printf("[INFO] Creating TOR circuits\n");
			
			// ... todo

			nextStep = 10000;

			printf("\n\n[INFO] SYSTEM READY! Type help for commands.\n\n");

			// Start heap-leak warning watch
			HEAP_LEAK_CHECK = Briand::BriandESPDevice::GetFreeHep(); // TODO + Briand::BriandESPDevice::GetFreePsram();

			if (VERBOSE) printf("[INFO] Free heap at system start is %u bytes.\n", HEAP_LEAK_CHECK);
		}
		else if (nextStep == 10000) {
			// Here system ready for commands
			printf("briand toresp32 > ");
			startSerialRead(COMMAND.get());
			nextStep = 10001;
		}
		else if (nextStep == 10001) {
			
			// Command received
			// Execute.....
			executeCommand( *(COMMAND.get()) );

			// Wait for next command
			nextStep = 10000;
		}
	}
}

/* Support functions */

void printLogo() {
	// Logo created with https://patorjk.com/software/taag/#p=display&f=Doom&t=TorEsp32
    printf("\n\n\n");
    printf(" _____            _____           _____  _____ \n");
    printf("|_   _|          |  ___|         |____ |/ __  \\\n");
    printf("  | | ___  _ __  | |__ ___ _ __      / /`' / /'\n");
    printf("  | |/ _ \\| '__| |  __/ __| '_ \\     \\ \\  / /  \n");
    printf("  | | (_) | |    | |__\\__ \\ |_) |.___/ /./ /___\n");
    printf("  \\_/\\___/|_|    \\____/___/ .__/ \\____/ \\_____/\n");
    printf("                          | |                  \n");
    printf("                          |_|                  \n");
    printf("                                               \n");
    printf("                VERSION 1.0.0                  \n");
    printf("              (Pandemic edition)               \n");
    printf("          Copyright (C) 2021 briand            \n");
    printf("        https://github.com/briand-hub          \n");
    printf("                                               \n");
}

void syncTimeWithNTP() {
	if (VERBOSE) printf("[INFO] Sync time to UTC+0 (no daylight saving) with NTP server %s\n", NTP_SERVER);

	//For UTC -5.00 : -5 * 60 * 60 : -18000
	//For UTC +1.00 : 1 * 60 * 60 : 3600
	//For UTC +0.00 : 0 * 60 * 60 : 0
	const long  gmtOffset_sec = 0;

	// to 3600 if daylight saving
	const int daylightOffset_sec = 0; 

	// MUST BE CONNECTED TO INTERNET!
		
	// Set timezone to UTC and no daylight saving
	// details: https://www.gnu.org/software/libc/manual/html_node/TZ-Variable.html
	setenv("TZ", "UTC", 1);
	tzset();

	// Perform sync
	//sntp_setoperatingmode(SNTP_SYNC_MODE_SMOOTH);
	
	sntp_setoperatingmode(SNTP_OPMODE_POLL);
	sntp_setservername(0, NTP_SERVER);
	sntp_init();

	if (VERBOSE) printf("[INFO] SNTP Time sync in progress...");

	// Wait until timeout or success
	int maxTentatives = 60; // = 30 seconds
	while (sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED && maxTentatives > 0) {
		maxTentatives--;
		vTaskDelay(500/portTICK_PERIOD_MS);
	}

	if (VERBOSE && maxTentatives > 0) printf("done.\n");
	if (VERBOSE && maxTentatives <= 0) printf("FAILED.\n");

	if (VERBOSE) printLocalTime();
}

void printLocalTime()
{
	printf("[INFO] UNIX time: %lu\n", Briand::BriandUtils::GetUnixTime());
}

void reboot() {
    // Cleanup
    WiFi->StopWIFI();

    // FS dismount
    esp_vfs_spiffs_unregister(NULL);

    // Serial stop
    fflush(stdout);
    
    // Restart
    esp_restart();
}

void startSerialRead(string* sPtr) {
    SERIAL_INPUT_POINTER = sPtr;
    SERIAL_INPUT_READING = true;
}

void executeCommand(string& cmd) {
	// Get heap size before command
	int heapBefore = static_cast<int>( esp_get_free_heap_size() );

    // Assign a command ID for external processing (will reset after max value for long tasks)
    if ( COMMANDID == ULLONG_MAX)
        COMMANDID = 0;
    else 
        COMMANDID++;

    printf("\n[CMD][0x%016llx]: %s\n", COMMANDID, cmd.c_str());
    printf("[EXE][0x%016llx]\n", COMMANDID);

	if (cmd.compare("help") == 0) {
        printf("COMMAND : description\n");
		printf("GENERAL---------------------------------------------------------------------------\n");
		printf("help : display this.\n");
        printf("time : display date and time.\n");
		printf("devinfo : display device information.\n");
		printf("meminfo : display short memory information.\n");
		printf("netinfo : display network STA/AP interfaces information.\n");
		printf("apoff : turn off AP interface.\n");
		printf("apon : turn on AP interface (will keep intact hostname/essid/password).\n");
		printf("torcache : print out the local node cache, all 3 files.\n");
        printf("torcache-refresh : refresh the tor cache.\n");
        printf("synctime : sync localtime time with NTP.\n");
		printf("reboot : restart device.\n");

		if (DEBUG) {
			printf("TESTING (DEBUG ACTIVE)--------------------------------------------------------\n");
			printf("search-guard : if DEBUG active, search and display info for a guard node.\n");
			printf("search-exit : if DEBUG active, search and display info for an exit node.\n");
			printf("search-middle : if DEBUG active, search and display info for a middle node.\n");
			printf("testcircuit : if DEBUG active, build a new circuit, resolve ifconfig.me IP then destroy just for testing.\n");
			printf("heapleak : if DEBUG active, leaks the heap to test leak warning.\n");
		}

		printf("TOR TESTING-----------------------------------------------------------------------\n");
		printf("ifconfig.me : Show **REAL** ifconfig.me information (NON-TOR REQUEST, REAL ADDRESS).\n");
    }
    else if (cmd.compare("time") == 0) {
        printLocalTime();
    }
    else if (cmd.compare("torcache") == 0) {
        auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
        relaySearcher->PrintCacheContents();
    }
    else if (cmd.compare("torcache-refresh") == 0) {
        auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
        relaySearcher->InvalidateCache(true);
    }
	else if (cmd.compare("synctime") == 0) {
        syncTimeWithNTP();
    }
    else if (cmd.compare("devinfo") == 0) {
        printf("CPU Frequency: %luMHz\n", Briand::BriandESPDevice::GetCpuFreqMHz());
        printf("Heap size: %lu bytes\n", Briand::BriandESPDevice::GetHeapSize());
        printf("Free heap: %u bytes\n", esp_get_free_heap_size());
		// TODO printf("PSram size: %d bytes\n", Briand::BriandESPDevice::GetPsramSize());
        // TODO printf("Free PSram: %d bytes\n", Briand::BriandESPDevice::GetFreePsram());
        
		unsigned int total = 0, used = 0;
		esp_spiffs_info(NULL, &total, &used);
		printf("File system size: %d bytes\n", total);
        printf("File system used: %d bytes\n", used);
        printf("File system free: %d bytes\n", (total-used));
    }
	else if (cmd.compare("meminfo") == 0) {
        // TODO printf("HEAP FREE: %u / %u bytes. PSRAM FREE: %u / %u bytes.\n", esp_get_free_heap_size(), Briand::BriandESPDevice::GetHeapSize(), Briand::BriandESPDevice::GetFreePsram(), Briand::BriandESPDevice::GetPsramSize());
		printf("HEAP FREE: %u / %lu bytes.\n", esp_get_free_heap_size(), Briand::BriandESPDevice::GetHeapSize());
    }
	else if (cmd.compare("netinfo") == 0) {
        printf("AP Hostname: %s\n", AP_HOSTNAME->c_str());
		printf("AP MAC: %s\n", WiFi->GetApMAC().c_str());
		printf("AP IP: %s\n", WiFi->GetApIP().c_str());
		printf("AP SSID: %s\n", AP_ESSID->c_str());
		printf("AP Password: %s\n", AP_PASSW->c_str());
        printf("STA Hostname: %s\n", STA_HOSTNAME->c_str());
        printf("STA MAC: %s\n", WiFi->GetStaMAC().c_str());
        printf("STA IPv4: %s\n",WiFi->GetStaIP().c_str());
		//printf("STA IPv6: %s\n", WiFi.localIPv6().toString().c_str());
		//printf("STA GW: %s\n", WiFi.gatewayIP().toString().c_str());
    }
	else if (cmd.compare("reboot") == 0)  {
        printf("Device will reboot now.\n");
		reboot();
    }
	else if (cmd.compare("apoff") == 0)  {
		// if (WiFi->StopAP()) printf("AP has been turned off.\n");
		// else printf("[ERR] Error turning off AP.\n");
		WiFi->StopAP();
    }
	else if (cmd.compare("apon") == 0)  {
		if (WiFi->StartAP(*AP_ESSID.get(), *AP_PASSW.get(), 13, 1, true)) {
			if(VERBOSE) printf("AP Ready. ESSID: %s PASSWORD: %s\n", AP_ESSID->c_str(), AP_PASSW->c_str());
		}
		else {
			printf("[ERR] Error on AP init! Only serial communication is enabled.\n");
		}
    }
	else if (cmd.compare("search-guard") == 0 && DEBUG)  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetGuardRelay();
        
		if (relay != nullptr && relay->FetchDescriptorsFromAuthority())
            printf("SUCCESS\n");
		else 
			printf("FAILED\n");

        relay->PrintRelayInfo();
    }
	else if (cmd.compare("search-exit") == 0 && DEBUG)  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetExitRelay("", "");
        
		if (relay != nullptr && relay->FetchDescriptorsFromAuthority())
			printf("SUCCESS\n");
		else 
			printf("FAILED\n");
        
        relay->PrintRelayInfo();
    }
	else if (cmd.compare("search-middle") == 0 && DEBUG)  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetMiddleRelay("");
		
		if (relay != nullptr && relay->FetchDescriptorsFromAuthority())
			printf("SUCCESS\n");
		else 
			printf("FAILED\n");

        relay->PrintRelayInfo();
    }
	else if (cmd.compare("testcircuit") == 0 && DEBUG)  {
		auto tempCircuit = make_unique<Briand::BriandTorCircuit>();
		
		if (tempCircuit->BuildCircuit()) {
			printf("SUCCESS! Cuircuit built!\n");
            tempCircuit->PrintCircuitInfo();
			tempCircuit->TorResolve("ifconfig.me");
		}
		else 
			printf("FAILED to build a circuit.\n");
    }
	else if (cmd.compare("heapleak") == 0 && DEBUG)  {
		auto leakingHeap = make_unique<unsigned char[]>(2048);
		// release instead of reset
		leakingHeap.release();
		printf("Heap has been leaked for 2048 bytes.\n");
    }
	else if (cmd.compare("ifconfig.me") == 0)  {
		string info = Briand::BriandUtils::BriandIfConfigMe();
		printf("\nInfo about your real identity:\n\n%s\n", info.c_str());
    }
	
	// other commands implementation...
    else {
        printf("Unknown command.\n");
    }

    printf("[EXE][0x%016llx][END]\n", COMMANDID);

	// Debug: print memory used by command
    int consumption = (heapBefore - static_cast<int>(esp_get_free_heap_size()));
	if (DEBUG) printf("[DEBUG] Heap consumption: %d (from %d to %d) bytes.\n", consumption, heapBefore, esp_get_free_heap_size());

    // Always useful: check if code has heap leaks 
    // sometimes I do the mistake to use .release() insted of .reset() on smart pointers :P	

	double testHeapLeak = static_cast<double>( HEAP_LEAK_CHECK - esp_get_free_heap_size() );
	testHeapLeak = testHeapLeak / static_cast<double>(HEAP_LEAK_CHECK);
	testHeapLeak = testHeapLeak * 100.0;
	
    if ( static_cast<char>( testHeapLeak ) >= HEAP_LEAK_LIMIT ){
        printf("[HEAP WARNING] !!!!!!!!!!WARNING!!!!!!!!! Heap is decreasing!\n");
		// reset
		HEAP_LEAK_CHECK = esp_get_free_heap_size();
    }
    
    // Clear COMMAND for next
    COMMAND->clear();
}

