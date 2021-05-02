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

/* Standard C++ libraries */
#include <iostream>
#include <memory>
#include <climits>
#include <time.h>

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
unsigned short nextStep = 0;
bool SERIAL_INPUT_READING = false;
string* SERIAL_INPUT_POINTER = nullptr;
unique_ptr<string> CONFIG_PASSWORD = nullptr;
unique_ptr<string> SERIAL_ENC_KEY = nullptr;
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
void TorEsp32Main();

// MAIN METHOD
void app_main() {
	// Call setup
	TorEsp32Setup();
	// Start application
	TorEsp32Main();
}

void TorEsp32Setup() {

}

void TorEsp32Main() {

}