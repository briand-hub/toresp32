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

/* Global parameters and includes (change it if you want by editing global file) */
#include "BriandDefines.hxx"

/* Project libraries */
#include "BriandTorEsp32Config.hxx"
#include "BriandTorAes.hxx"
#include "BriandUtils.hxx"
#include "BriandNet.hxx"
#include "BriandTorRelay.hxx"
#include "BriandTorCircuit.hxx"
#include "BriandTorCryptoUtils.hxx"
#include "BriandTorCircuitsManager.hxx"
#include "BriandTorSocks5Proxy.hxx"
#include "BriandTorStatistics.hxx"
#include "BriandTorDirAuthority.hxx"

/* Startup tests */

using namespace std;

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
unique_ptr<string> LAST_COMMAND = nullptr;
unique_ptr<string> COMMAND = nullptr;
unique_ptr<Briand::BriandTorCircuitsManager> CIRCUITS_MANAGER = nullptr;
unique_ptr<Briand::BriandTorSocks5Proxy> SOCKS5_PROXY = nullptr;
unsigned long HEAP_MAX = 0;
unsigned long HEAP_MIN = ULONG_MAX;
/** Flags for STA: LSB (bit 1) = autoreconnect, bit 2 set = disconnect, bit 3 set = connect/reconnect, MSB => reserved for not fire event each time before completed  */
unsigned char STA_ACTIONFLAGS = 0b00000001;
unsigned short proxyCustomPort = 0;

/* Early declarations */
void reboot();
void syncTimeWithNTP();
void printLocalTime();
void printLogo();
void startSerialRead(string*);
void executeCommand(string&);
void heapStats();
void checkStaHealth();

// Early declarations for setup/application
void TorEsp32Setup();
void TorEsp32Main(void* taskParam);

// MAIN METHOD
void app_main() {
	// Call setup
	TorEsp32Setup();

	// Start Heap monitor

	auto pcfg = esp_pthread_get_default_config();
	pcfg.thread_name = "HeapStats";
	pcfg.stack_size = STACK_HeapStats;
	pcfg.prio = 1000;
	esp_pthread_set_cfg(&pcfg);

	std::thread t1;

	do {
		t1 = std::thread(heapStats);

		// Check correct thread creation
		if (!t1.joinable()) {
			ESP_LOGE("toresp32", "[ERR] Error on starting heap stat pthread. Auto-retrying.\n");
			vTaskDelay(500 / portTICK_PERIOD_MS);
		}
		else {
			t1.detach();
			break;
		}
	} while (!t1.joinable());

	// Start application loop
	// This MUST remain a IDF task, otherwise serial input will not work well!!
	xTaskCreate(TorEsp32Main, "TorEsp32", STACK_TorEsp32, NULL, 5, NULL);

	// pcfg.thread_name = "TorEsp32";
	// pcfg.stack_size = STACK_TorEsp32;
	// pcfg.prio = 5;
	// esp_pthread_set_cfg(&pcfg);
	// std::thread t2(TorEsp32Main);
	// t2.detach();
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
	LAST_COMMAND = make_unique<string>("");

	// Common for error testing
	esp_err_t ret;

	// Disable default ESP log to Error only, set the log of this code to WARNING by default
	printf("[INFO] Setting ESP default log level to error...\n");
	esp_log_level_set("*", ESP_LOG_ERROR);
	BRIAND_SET_LOG("*", ESP_LOG_ERROR);

	// Initialize the NVS
	printf("[INFO] Initializing NVS...");
	ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);
	printf("done.\n");

    // De-buffered serial communication
	printf("[INFO] Unbuffering stdout...");
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("done.\n");
	printf("[INFO] Unbuffering stdin...");
	setvbuf(stdin, NULL, _IONBF, 0);
	printf("done.\n");

    printf("[INFO] Entering step %d\n", nextStep);
    
	// Initialize SPIFFS File System
	
	printf("[INFO] Initializing SPIFFS file system...");
	
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
			printf("FAILED! (mont error)\n");
		}
		else if (ret == ESP_ERR_NOT_FOUND) {
			printf("FAILED! (failed to find SPIFFS partition)\n");
		}
		else {
			printf("FAILED! reason: %s\n", esp_err_to_name(ret));
		}
		
		return; // Will create panic
	}

	printf("done.\n");
	
	unsigned int total = 0, used = 0;
	ret = esp_spiffs_info(conf.partition_label, &total, &used);
	if (ret != ESP_OK) {
		printf("[INFO] Failed to get SPIFFS partition information: %s\n", esp_err_to_name(ret));
	}	
	else {
		printf("[INFO] Partition size: total: %d used: %d bytes.\n", total, used);
	} 

    {
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
		auto bufV = Briand::BriandUtils::ArrayToVector(buf, test.length());
        printf("[TEST] Decrypted Bytes: <%s>\n", config->Decrypt(bufV).c_str());
        printf("[TEST] Took %llu milliseconds.\n", (esp_timer_get_time() - testStart)/1000L);
        printf("[TEST] AES Test success.\n");
		buf.reset();
		bufV.reset();
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
	
	printf("[INFO] Initializing WiFi\n");

	WiFi = Briand::BriandIDFWifiManager::GetInstance();
	WiFi->SetVerbose(false, true);

	// Init STA and AP random hostnames

	STA_HOSTNAME->append( Briand::BriandUtils::GetRandomHostName().get() );
	AP_HOSTNAME->append( Briand::BriandUtils::GetRandomHostName().get() );
	
	// High processor frequency
	// No more needed, done in config
	printf("[INFO] Setting CPU speed to 240MHz\n");
	Briand::BriandESPDevice::SetCpuFreqMHz(240);
	printf("[INFO] Current CPU speed is %lu MHz.\n", Briand::BriandESPDevice::GetCpuFreqMHz());

    // Print welcome
    printLogo();

    printf("[INFO] Serial communication: press [ENTER] to confirm inputs/commands. BACKSPACE *MAY* not work!\n\n\n");

    nextStep = 1; // setup success
}

void TorEsp32Main(void* taskParam) {
	// An xTask cannot return!
	while (1) {
		// If during serial input reading, wait while the command is entered and confirmed.
		if (SERIAL_INPUT_READING) {
			char in = (char)fgetc(stdin);

			// Check arrows
			if (in == 0x1B) {
				char in2 = (char)fgetc(stdin);
				char in3 = (char)fgetc(stdin);

				if (in2 == 0x5B && in3 == 0x41) {
					// UP: take last command, cancel the input and echo serial command
					while (SERIAL_INPUT_POINTER->length() > 0) {
						SERIAL_INPUT_POINTER->resize(SERIAL_INPUT_POINTER->length() - 1);
						// print backspace-like in order to clear input
						printf("%c %c", 0x08, 0x08);
					}

					// Assign command and print out
					SERIAL_INPUT_POINTER->assign(*LAST_COMMAND.get());
					printf("%s", LAST_COMMAND->c_str());
				}
				else if (in2 == 0x5B && in3 == 0x42) {
					// DOWN: reset all
					while (SERIAL_INPUT_POINTER->length() > 0) {
						SERIAL_INPUT_POINTER->resize(SERIAL_INPUT_POINTER->length() - 1);
						// print backspace-like in order to clear input
						printf("%c %c", 0x08, 0x08);
					}
				}

				// set in to 0xFF so no echo will be printed and nothing else will be done
				in = 0xFF;
			}

			if (in != 13 && in != 10 && in > 0 && in != 0xFF) {
				// Backspace handling
				if (in == 8 && SERIAL_INPUT_POINTER->length() > 0) {
					SERIAL_INPUT_POINTER->resize(SERIAL_INPUT_POINTER->length() - 1);

					// Mod for linux porting (not need to echo)
					#if defined(ESP_PLATFORM)
					// To "show" backspace print backspace, then a space and a new backspace
					printf("%c %c", in, in);
					#endif
				}
				else if (in != 8) {
					SERIAL_INPUT_POINTER->push_back(in);

					// Mod for linux porting (not need to echo)
					#if defined(ESP_PLATFORM)
					printf("%c", in);
					#endif
				}
			}
			else if (in == 13 || in == 10) {
				SERIAL_INPUT_READING = false;
				SERIAL_INPUT_POINTER = nullptr;

				// "Show" >ENTER< char
				printf("\n");

				// de-buffer (terminal "sticky" keys) (ONLY if running on ESP, on Linux will be infinite loop!)
				#if defined(ESP_PLATFORM)
				while (in != 0xFF) in = (char)fgetc(stdin);
				#endif
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
			ESP_LOGD("toresp32", "  >Entered: %s\n", STA_ESSID->c_str());
			printf("Connect to WiFi - PASSWORD: ");
			nextStep = 5;
			startSerialRead(STA_PASSW.get());
		}
		else if (nextStep == 5) {
			// Got Password, connect
			ESP_LOGD("toresp32", "  >Entered: %s\n", STA_PASSW->c_str());
			nextStep = 6;
		}
		else if (nextStep == 6) {
			// Connect station, until timeout reached.
			printf("[INFO] Connecting to %s ...", STA_ESSID->c_str());

			if (!WiFi->ConnectStation(*STA_ESSID.get(), *STA_PASSW.get(), WIFI_CONNECTION_TIMEOUT, *STA_HOSTNAME.get(), CHANGE_MAC_TO_RANDOM)) {
				ESP_LOGE("toresp32", "\n\n[ERR] WIFI CONNECTION ERROR/TIMEOUT. SYSTEM WILL RESTART IN 5 SECONDS!\n");
				vTaskDelay(5000 / portTICK_PERIOD_MS);
				reboot();
			}

			printf("connected!\n");

			printf("[INFO] STA MAC: %s\n", WiFi->GetStaMAC().c_str());
			printf("[INFO] LAN IP Address: %s\n", WiFi->GetStaIP().c_str());

			// Start WiFi Check

			auto pcfg = esp_pthread_get_default_config();
			pcfg.thread_name = "StaCheck";
			pcfg.stack_size = STACK_StaCheck;
			pcfg.prio = 500;
			esp_pthread_set_cfg(&pcfg);

			std::thread t;

			do {
				t = std::thread(checkStaHealth);

				// Check correct thread creation
				if (!t.joinable()) {
					ESP_LOGE("toresp32", "[ERR] Error on starting STA check pthread. Auto-retrying.\n");
					vTaskDelay(500 / portTICK_PERIOD_MS);
				}
				else {
					t.detach();
					break;
				}
			} while (!t.joinable());

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
				printf("[INFO] Configuration file written!\n");
			}
			else {
				printf("\n[INFO] Password must be 16 chars! Configuration file NOT written!\n");
			}

			// Now cleanup not anymore needed infos
			CONFIG_PASSWORD.reset();

			// Initialize AP interface

			printf("[INFO] Now initializing AP interface...\n");

			AP_ESSID = make_unique<string>(Briand::BriandUtils::GetRandomSSID().get());
			AP_PASSW = make_unique<string>(Briand::BriandUtils::GetRandomPassword(WIFI_AP_PASSWORD_LEN).get());
			//if (WiFi.softAP(apEssid.get(), apPassword.get(), WIFI_AP_CH, WIFI_AP_HIDDEN, WIFI_AP_MAX_CONN)) {
			if (WiFi->StartAP(*AP_ESSID.get(), *AP_PASSW.get(), WIFI_AP_CH, WIFI_AP_MAX_CONN, CHANGE_MAC_TO_RANDOM)) {
				printf("[INFO] AP Ready. ESSID: %s PASSWORD: %s\n", AP_ESSID->c_str(), AP_PASSW->c_str());
				
				// Change default ip
				WiFi->SetApIPv4(10, 0, 0, 1);
			}
			else {
				ESP_LOGE("toresp32", "[ERR] Error on AP init! Only serial communication is enabled.\n");
			}

			// Proceed to next step
			nextStep = 9;
		}
		else if (nextStep == 9) {

			// Sync time with NTP (VERY IMPORTANT!)
			syncTimeWithNTP();

			printf("[INFO] Free heap at system start is %zu bytes.\n", Briand::BriandESPDevice::GetFreeHeap());

			// Proceed to next steps
			nextStep = 1000;
		}
		else if (nextStep == 1000) {
			if (BUILTIN_LED_MODE == 0) {
				// Turn off
				printf("[INFO] Turning OFF built led %d\n", GPIO_NUM_5);
				gpio_set_level(GPIO_NUM_5, 1); // 1 => off, 0 => on
			}

			// Call method to get the best dir (will be saved in TOR_DIR_LAST_USED)
			briand_find_best_dir();


			printf("[INFO] Starting TOR Circuits Manager.\n");
			CIRCUITS_MANAGER = make_unique<Briand::BriandTorCircuitsManager>(TOR_CIRCUITS_KEEPALIVE, TOR_CIRCUITS_MAX_TIME_S, TOR_CIRCUITS_MAX_REQUESTS);
			
			// Builtin led handling
			gpio_set_direction(GPIO_NUM_5, GPIO_MODE_OUTPUT);
			gpio_set_level(GPIO_NUM_5, 1); // initial status OFF
			
			CIRCUITS_MANAGER->Start();

			printf("[INFO] TOR Circuits Manager started: %s\n", (CIRCUITS_MANAGER->IsStarted() ? "success" : "***ERROR! MANUAL START REQUIRED.***" ));

			if (CIRCUITS_MANAGER->IsStarted()) {
				printf("[INFO] Waiting for at least one suitable circuit, may take some time...\n");

				while (CIRCUITS_MANAGER->GetCircuit() == nullptr) {
					vTaskDelay(1000/portTICK_PERIOD_MS);
				}

				// Start the Proxy
				printf("[INFO] Starting SOCKS5 Proxy.\n");
				SOCKS5_PROXY = make_unique<Briand::BriandTorSocks5Proxy>();
				SOCKS5_PROXY->StartProxyServer(TOR_SOCKS5_PROXY_PORT, CIRCUITS_MANAGER);
				SOCKS5_PROXY->PrintStatus();
				printf("[INFO] SOCKS5 Proxy started.\n");

				if (BUILTIN_LED_MODE == 1) {
					// The led here should be turned ON
					printf("[INFO] Turning ON built led %d\n", GPIO_NUM_5);
					gpio_set_level(GPIO_NUM_5, 0); // initial status ON
				}
			}
			
			printf("\n\n[INFO] SYSTEM READY! Type help for commands.\n\n");

			nextStep = 10000;
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
    printf("                VERSION 1.1.0                  \n");
    printf("              (Pandemic edition)               \n");
    printf("          Copyright (C) 2021 briand            \n");
    printf("        https://github.com/briand-hub          \n");
    printf("                                               \n");
}

void syncTimeWithNTP() {
	printf("[INFO] Sync time to UTC+0 (no daylight saving) with NTP server %s\n", NTP_SERVER);

	//For UTC -5.00 : -5 * 60 * 60 : -18000
	//For UTC +1.00 : 1 * 60 * 60 : 3600
	//For UTC +0.00 : 0 * 60 * 60 : 0
	//const long  gmtOffset_sec = 0;

	// to 3600 if daylight saving
	//const int daylightOffset_sec = 0; 

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

	ESP_LOGI("toresp32", "[INFO] SNTP Time sync in progress...");

	// Wait until timeout or success
	int maxTentatives = 60; // = 30 seconds
	while (sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED && maxTentatives > 0) {
		maxTentatives--;
		vTaskDelay(500/portTICK_PERIOD_MS);
	}

	if (maxTentatives > 0) ESP_LOGI("toresp32", "done.\n");
	if (maxTentatives <= 0) ESP_LOGI("toresp32", "FAILED.\n");

	printLocalTime();
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

	// Turn off led
	gpio_set_direction(GPIO_NUM_5, GPIO_MODE_OUTPUT);
	gpio_set_level(GPIO_NUM_5, 1);
    
    // Restart
    esp_restart();
}

void startSerialRead(string* sPtr) {
    SERIAL_INPUT_POINTER = sPtr;
    SERIAL_INPUT_READING = true;
}

void executeCommand(string& cmd) {
	// Get heap size before command
	//int heapBefore = static_cast<int>( esp_get_free_heap_size() );

	if (cmd.compare("help") == 0) {
        printf("COMMAND : description\n");
		printf("SYSTEM-------------------------------------------------------------------------------\n");
		printf("help : display this.\n");
        printf("time : display date and time.\n");
		printf("devinfo : display device information.\n");
		printf("meminfo : display short memory information.\n");
		printf("netinfo : display network STA/AP interfaces information.\n");
		printf("taskinfo : shows running tasks details.\n");
		printf("staoff : disconnect STA.\n");
		printf("staon : connect/reconnect STA.\n");
		printf("stareconnect [on|off] : autoreconnect/do not autoreconnect STA.\n");
		printf("apoff : turn off AP interface.\n");
		printf("apon : turn on AP interface (will keep intact essid/password).\n");
		printf("apnew : turn on AP interface (will CHANGE essid/password).\n");
        printf("synctime : sync localtime time with NTP.\n");
		printf("log [TAG] [N/E/W/I/D/V] : Sets the log level of specified tag,  type help log for details.\n");
		printf("help log : Show details about log command.\n");
		printf("reboot : restart device.\n");

		if (esp_log_level_get("toresp32") == ESP_LOG_DEBUG) {
			printf("TESTING (active in DEBUG)---------------------------------------------------------\n");
			printf("search-guard : if DEBUG active, search and display info for a guard node.\n");
			printf("search-exit : if DEBUG active, search and display info for an exit node.\n");
			printf("search-middle : if DEBUG active, search and display info for a middle node.\n");
			printf("testcircuit : if DEBUG active, build a new circuit, resolve www.torproject.org IP then destroy just for testing.\n");
			printf("heapcircuit : if DEBUG active, prints heap size info of the first ready circuit.\n");
		}

		printf("TOR TESTING---------------------------------------------------------------------------\n");
		printf("myrealip : Show **REAL** IP address using (NON-TOR REQUEST).\n");
		printf("torip : Show **TOR** IP address (TOR REQUEST, uses proxy on 127.0.0.1).\n");

		printf("TOR COMMANDS--------------------------------------------------------------------------\n");
		printf("torcache : print out the local node cache, all 3 files.\n");
        printf("torcache refresh : refresh the tor cache.\n");
		printf("torcircuits : print out the current tor circuit status.\n");
		printf("torcircuits [restart|stop] : Invalidate all circuits pool, if restart rebuild again.\n");
		printf("torproxy [start|stop|status] : Starts/Stops/Prints info SOCKS5 Proxy.\n");
		printf("torproxyport [PORT] : Restarts the proxy on the provided custom port.\n");
		printf("tor resolve [hostname] : Resolve IPv4 address through tor.\n");
		printf("torstats : Prints tor statistics (even if proxy disabled).\n");
    }
    else if (cmd.compare("time") == 0) {
        printLocalTime();
    }
    else if (cmd.compare("synctime") == 0) {
        syncTimeWithNTP();
    }
	else if(cmd.compare("help log") == 0) {
		printf("This command sets the ESP logging function to desidered level for the specified tag.\n");
		printf("type: log [TAG] [LEVEL]\n");
		printf("[LEVEL] could be one of: [N]one, [E]rror, [W]arning, [I]nfo, [D]ebug, [V]erbose.\n");
		printf("example: <log wifi V> sets the WiFi log level to Verbose\n");
		printf("[TAG] could be one of the default ESP log tags or one of this system:\n");
		printf("TorEsp32 tags are:\n");
		printf("\t toresp32 : main loop.\n");
		printf("\t briandnet : the networking helper.\n");
		printf("\t briandcell : the cell component.\n");
		printf("\t briandcert : the certificate helper.\n");
		printf("\t briandcircuit : the circuit component.\n");
		printf("\t briandstream : the circuit streaming component.\n");
		printf("\t briandcircmgr : the circuits manager component.\n");
		printf("\t briandcrypto : the cryptographics helper.\n");
		printf("\t briandrelay : the relay component.\n");
		printf("\t briandsearch : the relay searcher component.\n");
		printf("\t briandproxy : the proxy component.\n");
		printf("\t briandutils : the misc utilities helper.\n");
		printf("Some of the ESP system tags are: wifi, wifi_init, esp_netif_handler, phy, system_api, tcpip_adapter, esp_netif_lwip, esp_netif_handlers, device, dhcpc ...\n");
		printf("\t Using tag wildcard * sets ALL the logs to the level specified.\n");
		printf("WARNING: setting high log level could cause unexpected crashes due to limited stack sizes and printf's high use of stack!!\n");
	}
	else if (cmd.length() > 3 && cmd.substr(0,4).compare("log ") == 0) {

		#if SUPPRESSLOG
		printf("*** Warning: log is suppressed, change by setting SUPPRESSDEBUGLOG to 0 in BriandDefines.hxx files and recompile.\n");
		#endif

		cmd.erase(0, 4);
		auto lPos = cmd.find(' ');
		if (lPos == string::npos) printf("Wrong format for command. Type help log.\n");
		const char* tag = cmd.substr(0, lPos).c_str();
		cmd.erase(0, lPos+1);
		if (cmd.compare("N") == 0) {
			esp_log_level_set(tag, ESP_LOG_NONE);
			BRIAND_SET_LOG(tag, ESP_LOG_NONE);
		} 
		else if (cmd.compare("E") == 0) {
			esp_log_level_set(tag, ESP_LOG_ERROR);
			BRIAND_SET_LOG(tag, ESP_LOG_ERROR);
		} 
		else if (cmd.compare("W") == 0) {
			esp_log_level_set(tag, ESP_LOG_WARN);
			BRIAND_SET_LOG(tag, ESP_LOG_WARN);
		} 
		else if (cmd.compare("I") == 0) {
			esp_log_level_set(tag, ESP_LOG_INFO);
			BRIAND_SET_LOG(tag, ESP_LOG_INFO);
		} 
		else if (cmd.compare("D") == 0) {
			esp_log_level_set(tag, ESP_LOG_DEBUG);
			BRIAND_SET_LOG(tag, ESP_LOG_DEBUG);
		} 
		else if (cmd.compare("V") == 0) {
			esp_log_level_set(tag, ESP_LOG_VERBOSE);
			BRIAND_SET_LOG(tag, ESP_LOG_VERBOSE);
		} 
		else printf("Wrong format for command. Type help log.\n");
	}
    else if (cmd.compare("devinfo") == 0) {
        printf("CPU Frequency: %luMHz\n", Briand::BriandESPDevice::GetCpuFreqMHz());
		
		Briand::BriandESPDevice::PrintMemoryStatus();
        
		unsigned int total = 0, used = 0;
		esp_spiffs_info(NULL, &total, &used);
		printf("File system size: %d bytes\n", total);
        printf("File system used: %d bytes\n", used);
        printf("File system free: %d bytes\n", (total-used));

		printf("\n");
    }
	else if (cmd.compare("meminfo") == 0) {
        Briand::BriandESPDevice::PrintMemoryStatus();
		printf("\n");
		printf("Max. heap free size: %lu\n", HEAP_MAX);
		printf("Min. heap free size: %lu\n", HEAP_MIN);
		printf("\n");
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
	else if (cmd.compare("taskinfo") == 0) {
        auto tinfo = Briand::BriandESPDevice::GetSystemTaskInfo();
		printf("%s\n", tinfo->c_str());
    }
	else if (cmd.compare("reboot") == 0)  {
        printf("Device will reboot now.\n");
		reboot();
    }
	else if (cmd.compare("staoff") == 0)  {
		STA_ACTIONFLAGS = STA_ACTIONFLAGS | 0b00000010;
    }
	else if (cmd.compare("staon") == 0)  {
		STA_ACTIONFLAGS = STA_ACTIONFLAGS | 0b00000100;
    }
	else if (cmd.compare("stareconnect on") == 0)  {
		STA_ACTIONFLAGS = STA_ACTIONFLAGS | 0b00000001;
		printf("Queued. See DEBUG/ERRORS.\n");
    }
	else if (cmd.compare("stareconnect off") == 0)  {
		STA_ACTIONFLAGS = STA_ACTIONFLAGS & ~(0b00000001);
		printf("Queued. See DEBUG/ERRORS.\n");
    } 
	else if (cmd.compare("apoff") == 0)  {
		// if (WiFi->StopAP()) printf("AP has been turned off.\n");
		// else printf("[ERR] Error turning off AP.\n");
		WiFi->StopAP();
    }
	else if (cmd.compare("apon") == 0)  {
		if (WiFi->StartAP(*AP_ESSID.get(), *AP_PASSW.get(), 13, 1, true)) {
			printf("AP Ready. ESSID: %s PASSWORD: %s\n", AP_ESSID->c_str(), AP_PASSW->c_str());
		}
		else {
			printf("[ERR] Error on AP init! Only serial communication is enabled.\n");
		}
    }
	else if (cmd.compare("apnew") == 0)  {
		AP_ESSID = make_unique<string>(Briand::BriandUtils::GetRandomSSID().get());
		AP_PASSW = make_unique<string>(Briand::BriandUtils::GetRandomPassword(WIFI_AP_PASSWORD_LEN).get());
		if (WiFi->StartAP(*AP_ESSID.get(), *AP_PASSW.get(), 13, 1, true)) {
			printf("NEW AP Ready. ESSID: %s PASSWORD: %s\n", AP_ESSID->c_str(), AP_PASSW->c_str());
		}
		else {
			printf("[ERR] Error on AP init! Only serial communication is enabled.\n");
		}
    }
	else if (cmd.compare("search-guard") == 0 && (esp_log_level_get("toresp32") == ESP_LOG_DEBUG))  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetGuardRelay();
        
		if (relay != nullptr/* Now in cache && relay->FetchDescriptorsFromAuthority()*/)
            printf("SUCCESS\n");
		else 
			printf("FAILED\n");

        relay->PrintRelayInfo();
    }
	else if (cmd.compare("search-exit") == 0 && (esp_log_level_get("toresp32") == ESP_LOG_DEBUG))  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetExitRelay("", "");
        
		if (relay != nullptr/* Now in cache && relay->FetchDescriptorsFromAuthority()*/)
			printf("SUCCESS\n");
		else 
			printf("FAILED\n");
        
        relay->PrintRelayInfo();
    }
	else if (cmd.compare("search-middle") == 0 && (esp_log_level_get("toresp32") == ESP_LOG_DEBUG))  {
		auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
		auto relay = relaySearcher->GetMiddleRelay("");
		
		if (relay != nullptr/* Now in cache && relay->FetchDescriptorsFromAuthority()*/)
			printf("SUCCESS\n");
		else 
			printf("FAILED\n");

        relay->PrintRelayInfo();
    }
	else if (cmd.compare("testcircuit") == 0 && (esp_log_level_get("toresp32") == ESP_LOG_DEBUG))  {
		auto tempCircuit = make_unique<Briand::BriandTorCircuit>();
		
		if (tempCircuit->BuildCircuit()) {
			printf("SUCCESS! Cuircuit built!\n");
            tempCircuit->PrintCircuitInfo();
			tempCircuit->TorResolve("ifconfig.me");
		}
		else 
			printf("FAILED to build a circuit.\n");
    }
	else if (cmd.compare("heapcircuit") == 0 && (esp_log_level_get("toresp32") == ESP_LOG_DEBUG))  {
		if (CIRCUITS_MANAGER == nullptr) {
			printf("Error, circuit manager not instanced.\n");
		}
		else {
			auto circ = CIRCUITS_MANAGER->GetCircuit();
			if (circ == nullptr) {
				printf("Error, no suitable circuit.\n");
			}
			else {
				printf("CIRCUIT OBJ ------------------------------------------------------------------------------\n");
				circ->CircuitInstance->PrintObjectSizeInfo();
				printf("------------------------------------------------------------------------------------------\n\n");
				printf("INTERNAL NODE OBJ (guard) ----------------------------------------------------------------\n");
				circ->CircuitInstance->guardNode->PrintObjectSizeInfo();
				printf("------------------------------------------------------------------------------------------\n");
			}
		}
    }
	else if (cmd.compare("myrealip") == 0)  {
		printf("Your real public ip is: %s\n", Briand::BriandUtils::GetPublicIP().c_str());
    }
	else if (cmd.compare("torip") == 0)  {
		if (SOCKS5_PROXY == nullptr) {
			printf("Proxy is not started. Use \"torproxy start\" command.\n");
		}
		else {
			SOCKS5_PROXY->SelfTest();
		}
    }
	// TOR commands
	else if (cmd.compare("torcircuits") == 0) {
		CIRCUITS_MANAGER->PrintCircuitsInfo();
	}
	else if (cmd.compare("torcircuits restart") == 0) {
		printf("Stopping CircuitsManager...");
		CIRCUITS_MANAGER->Stop();
		printf("done.\n");
		printf("Starting CircuitsManager...");
		CIRCUITS_MANAGER->Start();
		printf("done.\n");
	}
	else if (cmd.compare("torcircuits stop") == 0) {
		printf("Stopping CircuitsManager...");
		CIRCUITS_MANAGER->Stop();
		printf("done.\n");
	}
	else if (cmd.compare("torproxy start") == 0) {
		printf("Starting SOCKS5 Proxy on port %hu...", (proxyCustomPort != 0 ? proxyCustomPort : TOR_SOCKS5_PROXY_PORT));
		if (SOCKS5_PROXY == nullptr) SOCKS5_PROXY = make_unique<Briand::BriandTorSocks5Proxy>();
		SOCKS5_PROXY->StartProxyServer((proxyCustomPort != 0 ? proxyCustomPort : TOR_SOCKS5_PROXY_PORT), CIRCUITS_MANAGER);
		printf("done.\n");
	}
	else if (cmd.compare("torproxy stop") == 0) {
		printf("Stopping SOCKS5 Proxy...");
		if (SOCKS5_PROXY != nullptr) SOCKS5_PROXY->StopProxyServer();
		printf("done.\n");
	}
	else if (cmd.compare("torproxy status") == 0) {
		if (SOCKS5_PROXY != nullptr) {
			SOCKS5_PROXY->PrintStatus();
		}
		else {
			printf("Error, Proxy not instanced.\n");
		}
	}
	else if (cmd.substr(0,12).compare("torproxyport") == 0) {
		string temp = cmd.substr(13, cmd.length() - 13);
		if (Briand::BriandUtils::IsNumber(temp)) {
			proxyCustomPort = static_cast<unsigned short>(atoi(temp.c_str()));
			if (SOCKS5_PROXY != nullptr) {
				printf("Stopping proxy...");
				SOCKS5_PROXY->StopProxyServer();
				printf("done.\nRestarting proxy on port <%hu>...", proxyCustomPort);
				SOCKS5_PROXY->StartProxyServer(proxyCustomPort, CIRCUITS_MANAGER);
				printf("done.\n\n");
				SOCKS5_PROXY->PrintStatus();
			}
			else {
				printf("Starting proxy on port <%hu>...", proxyCustomPort);
				SOCKS5_PROXY = make_unique<Briand::BriandTorSocks5Proxy>();
				SOCKS5_PROXY->StartProxyServer(proxyCustomPort, CIRCUITS_MANAGER);
				printf("done.\n\n");
				SOCKS5_PROXY->PrintStatus();
			}
		}
		else {
			printf("Invalid port <%s>.\n", temp.c_str());
		}
	}
	else if (cmd.compare("torcache") == 0) {
        auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
        relaySearcher->PrintCacheContents();
    }
    else if (cmd.compare("torcache refresh") == 0) {
        auto relaySearcher = make_unique<Briand::BriandTorRelaySearcher>();
        relaySearcher->InvalidateCache(true);
    }
	else if (cmd.substr(0, 12).compare("tor resolve ") == 0) {
		cmd.erase(cmd.begin(), cmd.begin() + 12);
		auto circuit = CIRCUITS_MANAGER->GetCircuit();
		if (circuit == nullptr) {
			printf("No suitable circuit found.\n");
		}
		else {
			printf("Using circuit #%hu\n", circuit->CircuitInstance->internalID);
			// Lock the circuit
			unique_lock<mutex> lock(circuit->CircuitMutex);
			printf("IPv4 address: %s\n", Briand::BriandUtils::IPv4ToString(circuit->CircuitInstance->TorResolve(cmd)).c_str());
		}
	}
	else if (cmd.compare("torstats") == 0) {
		Briand::BriandTorStatistics::Print();
	}
	// other commands implementation...
    else {
        printf("Unknown command.\n");
    }
    
	printf("\n");

	// Save as last command
	LAST_COMMAND->assign(COMMAND->c_str());

    // Clear COMMAND for next
    COMMAND->clear();
}

void heapStats() {
	// IDF Task cannot return
	while (1) {
		unsigned long currentHeap = Briand::BriandESPDevice::GetFreeHeap();
		if (currentHeap > HEAP_MAX) HEAP_MAX = currentHeap;
		if (currentHeap < HEAP_MIN) HEAP_MIN = currentHeap;
		vTaskDelay(500 / portTICK_PERIOD_MS);
	}
}

void checkStaHealth() {
	// IDF Task cannot return
	while (1) {
		

		#if defined(__linux__)
			// On linux environment this must never fire (always set MSB to 1)
			STA_ACTIONFLAGS = STA_ACTIONFLAGS | 0b10000000;
		#endif

		// If MSB set, do not do anything!
		if ((STA_ACTIONFLAGS & 0b10000000) != 0b10000000) {
			// Set MSB (Busy)
			STA_ACTIONFLAGS = STA_ACTIONFLAGS | 0b10000000;

			// If LSB/bit 1 is set, then auto-reconnect if is not connected.
			if ((STA_ACTIONFLAGS & 0b00000001) == 0b00000001) {
				// Check if disconnected or IP is 0.0.0.0 (happens on low memory, does not fire any event)
				if (WiFi != nullptr && (!WiFi->IsConnected() || WiFi->GetStaIP().compare("0.0.0.0")==0)) {
					//WiFi->DisconnectStation(); // do not use this, will stuck in infinite loop.
					auto err = esp_wifi_connect();
					if (err != ESP_OK) {
						ESP_LOGE("toresp32", "[ERR] WiFi Re-connect failed, error %d\n", err);
					}
					else {
						ESP_LOGD("toresp32", "[DEBUG] WiFi Re-connect success.\n");
					}
				}
			}
			// If bit 2 is set, then disconnect and reset the bit.
			if ((STA_ACTIONFLAGS & 0b00000010) == 0b00000010) {
				if (WiFi != nullptr && WiFi->IsConnected()) {
					WiFi->DisconnectStation();
					printf("[INFO] WiFi disconnected as requested.\n");
				}
				else {
					printf("[INFO] WiFi is not connected.\n");
				}
				STA_ACTIONFLAGS = STA_ACTIONFLAGS & (~0b00000010);
			}
			// If bit 3 is set, then connect and reset the bit.
			if ((STA_ACTIONFLAGS & 0b00000100) == 0b00000100) {
				if (WiFi != nullptr && !WiFi->IsConnected()) {
					if (!WiFi->ConnectStation(*STA_ESSID.get(), *STA_PASSW.get(), WIFI_CONNECTION_TIMEOUT, *STA_HOSTNAME.get(), CHANGE_MAC_TO_RANDOM)) {
						printf("[INFO] ERROR: WiFi connect failed.\n");
					}
					else {
						printf("[INFO] WiFi connect success.\n");
					}
				}
				STA_ACTIONFLAGS = STA_ACTIONFLAGS & (~0b00000100);
			}

			// Reset MSB (Free)
			STA_ACTIONFLAGS = STA_ACTIONFLAGS & (~0b10000000);
		}

		vTaskDelay(2000 / portTICK_PERIOD_MS);
	}
}