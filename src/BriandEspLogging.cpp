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

        esp_log_level_t CURRENT_LOG_LEVEL = ESP_LOG_WARN;
        
        void BRIAND_SET_LOG(esp_log_level_t newLevel) { 
            CURRENT_LOG_LEVEL = newLevel; 
            esp_log_level_set(LOGTAG, newLevel);
        }
        
        esp_log_level_t esp_log_level_get(const char* logTag) { 
            return CURRENT_LOG_LEVEL; 
        }
    #endif

#elif defined(__linux__)

    void BRIAND_SET_LOG(esp_log_level_t newLevel) { 
        // There is the base function
        esp_log_level_set("*", newLevel);
    }

#else

    constexpr void BRIAND_SET_LOG(esp_log_level_t newLevel) { /* do nothing */ };

#endif /* defined(ESP_PLATFORM) */
