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

        typedef struct _briandLogTrick {
            const char* tag;
            esp_log_level_t level;
        } briandLogTrick;

        briandLogTrick CURRENT_LOG_LEVEL[64];
        unsigned char CURRENT_LOG_LEVEL_NEXT = 0;

        void BRIAND_SET_LOG(const char* tag, esp_log_level_t newLevel) { 
            bool found = false;
            for (unsigned char i = 0; i <= CURRENT_LOG_LEVEL_NEXT && !found; i++) {
                if (tag != NULL && CURRENT_LOG_LEVEL[i].tag != NULL && strcmp(CURRENT_LOG_LEVEL[i].tag, tag) == 0) {
                    CURRENT_LOG_LEVEL[i].level = newLevel;
                    found = true;
                }
            }

            if (!found) {
                CURRENT_LOG_LEVEL[CURRENT_LOG_LEVEL_NEXT].tag = tag;
                CURRENT_LOG_LEVEL[CURRENT_LOG_LEVEL_NEXT].level = newLevel;
                if (CURRENT_LOG_LEVEL_NEXT + 1 < 64) CURRENT_LOG_LEVEL_NEXT++;
            }

            esp_log_level_set(tag, newLevel);
        }
        
        esp_log_level_t esp_log_level_get(const char* tag) { 
            for (unsigned char i = 0; i <= CURRENT_LOG_LEVEL_NEXT; i++) {
                if (tag != NULL && CURRENT_LOG_LEVEL[i].tag != NULL && strcmp(CURRENT_LOG_LEVEL[i].tag, tag) == 0) {
                    return CURRENT_LOG_LEVEL[i].level;
                }
            }

            return ESP_LOG_NONE; 
        }

    #endif

#elif defined(__linux__)

    void BRIAND_SET_LOG(const char* tag, esp_log_level_t newLevel) { 
        // There is the base function
        esp_log_level_set("*", newLevel);
    }

#else

    constexpr void BRIAND_SET_LOG(const char* tag, esp_log_level_t newLevel) { /* do nothing */ };

#endif /* defined(ESP_PLATFORM) */
