
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

#include "BriandTorDirAuthority.hxx"

// Static member for the last responding authority
unsigned short TOR_DIR_LAST_USED = 0x0000;

/** retrieves the best directory for speed/connection and sets to TOR_DIR_LAST_USED */
void briand_find_best_dir() {
    printf("[INFO] Finding best authority directory, may take some time.\n");

    auto minOperTime = INT64_MAX;
    unsigned short minOperDir = TOR_DIR_AUTHORITIES_NUMBER + 1;

    for (unsigned short i = 0; i<TOR_DIR_AUTHORITIES_NUMBER; i++) {
        auto startTime = esp_timer_get_time();

        printf("[INFO]\t Contacting %s (%s:%hu)...", TOR_DIR_AUTHORITIES[i].nickname, TOR_DIR_AUTHORITIES[i].host, TOR_DIR_AUTHORITIES[i].port);

        // Try connect and download of its own descriptors located at http://[dir]:[dirport]/tor/server/fp/[dirfingerprint]
        auto client = make_unique<Briand::BriandIDFSocketClient>();
        client->SetReceivingBufferSize(512);
        // Use small timeouts
        client->SetTimeout(15, 15);
        client->SetVerbose(false);
        
        if (!client->Connect(TOR_DIR_AUTHORITIES[i].host, TOR_DIR_AUTHORITIES[i].port)) {
            // sure not this dir
            printf("connect failed.\n");
            continue;
        }

        auto request = make_unique<string>();
		request->append("GET /tor/server/fp/" + string(TOR_DIR_AUTHORITIES[i].fingerprint) + " HTTP/1.1\r\n");
		request->append("Connection: close\r\n");
		request->append("\r\n");
		
		auto requestV = Briand::BriandNet::StringToUnsignedCharVector(request, true);
        if (!client->WriteData(requestV)) {
            // sure not this dir
            printf("request failed.\n");
			client->Disconnect();		
			continue;
		}

        unique_ptr<vector<unsigned char>> data = nullptr;
        size_t bytes = 0;
        do {
            data = client->ReadData(true);
            if (data != nullptr) bytes += data->size();
        } while (data != nullptr && data->size() > 0);

        client->Disconnect();
        
        if (bytes > 0) {
            auto requiredTime = esp_timer_get_time() - startTime;
            if (requiredTime < minOperTime) {
                minOperTime = requiredTime;
                minOperDir = i;
            }
            printf("%zu bytes downloaded in %lld ms (%.0f B/s)\n", bytes, requiredTime/1000, bytes/(requiredTime/1000.0));
        }
        else {
            printf("download failed.\n");
        }
    }

    if (minOperDir == TOR_DIR_AUTHORITIES_NUMBER + 1) {
        printf("[INFO] Finding best authoriry directory finished with failure.\n");
        TOR_DIR_LAST_USED = 0;
    }
    else {
        printf("[INFO] Finding best authoriry directory finished: %s (%s) is best with %lld milliseconds.\n", TOR_DIR_AUTHORITIES[minOperDir].nickname, TOR_DIR_AUTHORITIES[minOperDir].host, (minOperTime/1000));
        // Save the best result
        TOR_DIR_LAST_USED = minOperDir;
    }
}