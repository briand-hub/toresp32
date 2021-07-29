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

#include "BriandTorSocks5Proxy.hxx"

#include "BriandUtils.hxx"

using namespace std;

namespace Briand
{
    BriandTorCircuitsManager* BriandTorSocks5Proxy::torCircuits = nullptr;

    BriandTorSocks5Proxy::BriandTorSocks5Proxy() {
        this->proxySocket = -1;
        this->torCircuits = nullptr;
        bzero(&this->proxyTaskHandle, sizeof(this->proxyTaskHandle));
    }

    BriandTorSocks5Proxy::~BriandTorSocks5Proxy() {
        this->StopProxyServer();
    }

    void BriandTorSocks5Proxy::StartProxyServer(unsigned short& port, unique_ptr<BriandTorCircuitsManager>& mgr) {
        // If the instance is/was created, stop the previous.
        this->StopProxyServer();

        this->torCircuits = mgr.get();
        if (this->torCircuits == nullptr) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy requires a valid CircuitsManager to run.\n");
            return;
        }

        // Prepare structure for server binding
        struct sockaddr_in serverAddr;
        bzero(&serverAddr, sizeof(serverAddr));
        serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);

        // Create a socket
        this->proxySocket = socket(AF_INET, SOCK_STREAM, 0);
        if (this->proxySocket < 0) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy unable to create socket.\n");
            return;
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy socket created.\n");

        // Bind the socket to the specified address
        if (bind(this->proxySocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) != 0) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy error on binding.\n");
            close(this->proxySocket);
            this->proxySocket = -1;
            return;
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy socket binding done.\n");

        // Listen for maximum 1 connection
        if (listen(this->proxySocket, 1) != 0) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy error on binding.\n");
            close(this->proxySocket);
            this->proxySocket = -1;
            return;
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy listening.\n");

        xTaskCreate(this->HandleRequest, "TorProxy", 2048, reinterpret_cast<void*>(this->proxySocket), 300, &this->proxyTaskHandle);

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy started.\n");
    }

    /* static */ void BriandTorSocks5Proxy::ErrorResponse(int socket, unsigned char* data, unsigned int dataLen) {
        if (socket > 0) {
            if (data != nullptr && dataLen > 0) {
                send(socket, data, dataLen, 0);
            }
            close(socket);
        }
    }

    /* static */ void BriandTorSocks5Proxy::HandleRequest(void* serverSocket) {
        // IDF task cannot return
        while (1) {
            if (serverSocket == NULL || serverSocket == nullptr) {
                vTaskDelete(NULL);
            }
            else {
                // Convert parameter
                int serverSock = (int)serverSocket;

                // Wait a connection
                struct sockaddr_in clientAddr;
                socklen_t clientAddrLen = sizeof(clientAddr);
                int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientAddrLen);

                if (clientSock < 0) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy cannot accept connection.\n");
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy accepted incoming connection from %s\n", BriandUtils::ipv4ToString(clientAddr.sin_addr).c_str());

                //
                // Very good example: https://www.programmersought.com/article/85795017726/
                // 

                auto recBuf = make_unique<unsigned char[]>(258);
                int len;

                // Check the first request, should be like 
                // ver |len | methods
                // 0x05|0xNN| NN times methods (max 255)

                len = recv(clientSock, recBuf.get(), 257, 0);

                if (len <= 0) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy methods receiving error. Closing connection.\n");
                    // Close client socket
                    ErrorResponse(clientSock, nullptr, 0);
                    continue;
                }
                
                if (len < 3) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy methods receiving error: less than 3 bytes. Closing connection.\n");
                    // Close client socket
                    ErrorResponse(clientSock, nullptr, 0);
                    continue;
                }

                if (recBuf[0] != 0x05 || recBuf[1] < 0x01) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: no auth method or wrong socks version. Closing connection.\n");
                    // Write back unsupported version / unsupported method and close
                    unsigned char temp[2] = { 0x05, 0xFF };
                    ErrorResponse(clientSock, temp, 2);
                    continue;
                }

                // Find if there is a suitable method (0x00 => no authentication is required)
                bool methodOk = false;
                for (unsigned int i = 2; i<len && i < recBuf[1] ; i++) {
                    if (recBuf[i] == 0x00) {
                        methodOk = true;
                        break;
                    }
                }

                if (!methodOk) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: no open auth method. Closing connection.\n");
                    // Write back unsupported version / unsupported method and close
                    unsigned char temp[2] = { 0x05, 0xFF };
                    ErrorResponse(clientSock, temp, 2);
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy client handshake ok.\n");

                // At this point client sends a request to connect

                recBuf = make_unique<unsigned char[]>(32);  // request could be max 22 bytes long
                len = recv(clientSock, recBuf.get(), 32, 0);

                if (len < 10) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy connect request receiving error. Closing connection.\n");
                    // Close client socket
                    ErrorResponse(clientSock, nullptr, 0);
                    continue;
                }

                // Only CONNECT supported at the moment
                if (recBuf[1] != 0x01) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: command %02X unsupported. Closing connection.\n", recBuf[1]);
                    // Write back unsupported version / unsupported method and close
                    unsigned char temp[4] = { 0x05, 0x07, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 6);
                    continue;
                }

                // Only IPv4 or host supported at the moment
                if (recBuf[3] == 0x03) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: IPv6 unsupported. Closing connection.\n");
                    // Write back unsupported version / unsupported method and close
                    unsigned char temp[4] = { 0x05, 0x08, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy finding suitable circuit.\n");

                if (BriandTorSocks5Proxy::torCircuits == nullptr) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: circuits manager not ready. Closing connection.\n");
                    // Write back network unreachable
                    unsigned char temp[4] = { 0x05, 0x03, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    continue;
                }

                BriandTorCircuit* circuit = BriandTorSocks5Proxy::torCircuits->GetCircuit();

                if (circuit == nullptr) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: no suitable circuit. Closing connection.\n");
                    // Write back network unreachable
                    unsigned char temp[4] = { 0x05, 0x03, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy connecting.\n");

                // Connect to the destination (RELAY_BEGIN)

                //
                // TODO
                // 

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy connected.\n");

                // Send OK Response to client

                //
                // TODO
                //

                //send(clientSock, /**/, 4);

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy streaming data.\n");

                do {
                    // In order to limit tor cells size, read maximum N bytes (maximum RELAY cell payload length)
                    constexpr unsigned short MAX_FREE_PAYLOAD = 498;
                    recBuf = make_unique<unsigned char[]>(MAX_FREE_PAYLOAD);
                    
                    // Read from client
                    len = recv(clientSock, recBuf.get(), MAX_FREE_PAYLOAD, 0);
                    if (len < 0) {
                        // ERROR
                        ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: read from client error. Closing connection.\n");
                        // Close connection
                        ErrorResponse(clientSock, nullptr, 0);
                        continue;
                    }
                    else if (len == 0) {
                        // No other data to stream, so send a RELAY_FINISH (???)

                        //
                        // TODO
                        // 

                    }
                    else {
                        // Send data through circuit (RELAY_DATA)

                        auto sendBuf = make_unique<vector<unsigned char>>();

                        // 
                        // TODO
                        // 

                        // If the length of received data is less than MAX_FREE_PAYLOAD
                        // there should be no other data to stream.
                        if (len < MAX_FREE_PAYLOAD) {
                            //
                            // TODO
                            // 
                        }
                    }

                } while (len > 0);

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy data sent, receiving response.\n");

                // Read back

                //
                // TODO
                //

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy finished.\n");
            }

            // Wait 1 second before next run
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
    }

    void BriandTorSocks5Proxy::StopProxyServer() {
        // If socket is ready then close and delete associated IDF Task
        if (this->proxySocket > 0) {
            ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy killing task.\n");    
            vTaskDelete(this->proxyTaskHandle);
            // Clean previous task
            bzero(&this->proxyTaskHandle, sizeof(this->proxyTaskHandle));
            ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy closing socket.\n");    
            close(this->proxySocket);
        }
        
        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy stopped.\n");
    }
}