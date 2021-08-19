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

// IDF <=v4.3 does not contain a esp_log_level_get function, but it is needed

#include "BriandDefines.hxx"

#if defined(ESP_PLATFORM)

    #if ESP_IDF_VERSION <= ESP_IDF_VERSION_VAL(4, 3, 0)

        // Define esp_log_level_get like the latest version, this is a trick

        #include <map>

        // Use an efficient map!
        map<string, esp_log_level_t> BRIAND_LOG_LEVEL_MAP;

        void BRIAND_SET_LOG(const char* tag, esp_log_level_t newLevel) { 
            // If wildcard, all to level.
            if (strcmp(tag, "*") == 0) {
                for (auto it = BRIAND_LOG_LEVEL_MAP.begin(); it != BRIAND_LOG_LEVEL_MAP.end(); ++it) {
                    it->second = newLevel;
                }
            }
            else {
                BRIAND_LOG_LEVEL_MAP[string(tag)] = newLevel;
            }

            esp_log_level_set(tag, newLevel);
        }
        
        esp_log_level_t esp_log_level_get(const char* tag) { 
            auto it = BRIAND_LOG_LEVEL_MAP.find(string(tag));
            if (it == BRIAND_LOG_LEVEL_MAP.end()) BRIAND_LOG_LEVEL_MAP[string(tag)] = ESP_LOG_NONE;
            return BRIAND_LOG_LEVEL_MAP[string(tag)]; 
        }

    #endif

#elif defined(__linux__)

    void BRIAND_SET_LOG(const char* tag, esp_log_level_t newLevel) { 
        // There is the base function
        esp_log_level_set(tag, newLevel);
    }

#else

    constexpr void BRIAND_SET_LOG(const char* tag, esp_log_level_t newLevel) { /* do nothing */ };

#endif /* defined(ESP_PLATFORM) */
