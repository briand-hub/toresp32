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

#include "BriandDefines.hxx"
#include "BriandTorSocks5Proxy.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand
{
    BriandTorCircuitsManager* BriandTorSocks5Proxy::torCircuits = nullptr;

    BriandTorSocks5Proxy::BriandTorSocks5Proxy() {
        this->proxySocket = -1;
        this->torCircuits = nullptr;
        this->proxyStarted = false;
        bzero(&this->proxyTaskHandle, sizeof(this->proxyTaskHandle));
    }

    BriandTorSocks5Proxy::~BriandTorSocks5Proxy() {
        this->StopProxyServer();
    }

    void BriandTorSocks5Proxy::StartProxyServer(const unsigned short& port, unique_ptr<BriandTorCircuitsManager>& mgr) {
        // If the instance is/was created, stop the previous.
        if (this->proxyStarted) this->StopProxyServer();

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

        xTaskCreate(this->HandleRequest, "TorProxy", 4096, reinterpret_cast<void*>(this->proxySocket), 300, &this->proxyTaskHandle);

        this->proxyStarted = true;

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

                if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
                    printf("[DEBUG] SOCKS5 Proxy (methods) received %d bytes: ", len);
                    BriandUtils::PrintOldStyleByteBuffer(recBuf.get(), len);
                }

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
                for (unsigned int i = 2; i<len && i < recBuf[1]+2 ; i++) {
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

                // Send OK Response to client
                {
                    unsigned char temp[2] = { 0x05, 0x00 };
                    send(clientSock, temp, 2, 0);
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy client waiting for request.\n");

                // At this point client sends a request to connect

                recBuf = make_unique<unsigned char[]>(32);  // request could be max 22 bytes long
                len = recv(clientSock, recBuf.get(), 32, 0);

                if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
                    printf("[DEBUG] SOCKS5 Proxy connect request received %d bytes: ", len);
                    BriandUtils::PrintOldStyleByteBuffer(recBuf.get(), len);
                }

                if (len < 10) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy connect request receiving error. Closing connection.\n");
                    // Close client socket
                    ErrorResponse(clientSock, nullptr, 0);
                    continue;
                }

                // Only CONNECT supported at the moment
                if (recBuf[1] != 0x01) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: command %02X unsupported. Closing connection.\n", recBuf[1]);
                    // Write back unsupported command and close
                    unsigned char temp[4] = { 0x05, 0x07, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    continue;
                }

                // Only IPv4 or host supported at the moment
                if (recBuf[3] == 0x04) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: unsupported atyp, must be IPv4 (0x01) or hostname (0x03). Closing connection.\n");
                    // Write back unsupported address type and close
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

                // Extract informations about host and port to connect to
                string connectTo = "";
                unsigned short connectPort = 0;
                
                if (recBuf[3] == 0x01) {
                    in_addr ip;
                    bzero(&ip, sizeof(ip));
                    // Assuming recBuf contains ip in human order
                    ip.s_addr += recBuf[4] << 0;
                    ip.s_addr += recBuf[5] << 8;
                    ip.s_addr += recBuf[6] << 16;
                    ip.s_addr += recBuf[7] << 24;

                    connectTo = BriandUtils::ipv4ToString(ip);

                    // Port
                    connectPort += recBuf[8] << 8;
                    connectPort += recBuf[9] << 0;

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy connecting to IP address <%s> on port <%hu>.\n", connectTo.c_str(), connectPort);
                }
                else if (recBuf[3] == 0x03) {
                    // First byte has length
                    unsigned char hostlen = recBuf[4];
                    unsigned short i = 5;
                    for (i=5; i<5+hostlen; i++)
                        connectTo.push_back(static_cast<char>(recBuf[i]));
                    
                    // Port
                    connectPort += recBuf[i] << 8;
                    connectPort += recBuf[i+1] << 0;

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy connecting to hostname <%s> on port <%hu>.\n", connectTo.c_str(), connectPort);
                }
                else {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: unsupported address type. Closing connection.\n");
                    // Write back unsupported address type and close
                    unsigned char temp[4] = { 0x05, 0x08, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    continue;
                }

                // Connect to the destination (RELAY_BEGIN)

                if (!circuit->TorStreamStart(connectTo, connectPort)) {
                    // Write back unable to connect (refused) and close
                    unsigned char temp[4] = { 0x05, 0x05, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy connected.\n");

                // Send OK Response to client
                {
                    unsigned char temp[4] = { 0x05, 0x00, 0x00, 0x01 /* omitted */ };
                    send(clientSock, temp, 4, 0);
                }

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
                        bool result = circuit->TorStreamEnd();
                        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy finished (%hu).\n", result);
                    }
                    else {
                        // Send data through circuit (RELAY_DATA)

                        auto sendBuf = make_unique<vector<unsigned char>>();
                        bool sent = false;

                        sendBuf->insert(sendBuf->begin(), recBuf.get(), recBuf.get() + len);
                        circuit->TorStreamSend(sendBuf, sent);

                        if (!sent) {
                            // ERROR
                            ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: data NOT sent. Closing connection.\n");
                            // Close connection
                            ErrorResponse(clientSock, nullptr, 0);
                            continue;
                        }

                        // If the length of received data is less than MAX_FREE_PAYLOAD
                        // there should be no other data to stream.
                        if (len < MAX_FREE_PAYLOAD) {
                            bool result = circuit->TorStreamEnd();
                            ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy finished (%hu).\n", result);
                        }
                    }

                } while (len > 0);

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy data sent, receiving response.\n");

                // Read back and send to the client

                //
                // TODO
                //

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy finished.\n");

                // Close the connection
                close(clientSock);
            }

            // Wait 1 second before next run
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
    }

    void BriandTorSocks5Proxy::StopProxyServer() {
        // If socket is ready then close and delete associated IDF Task
        if (this->proxyStarted) {
            ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy killing task.\n");    
            vTaskDelete(this->proxyTaskHandle);
            ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy closing socket.\n");    
            close(this->proxySocket);
            this->proxyStarted = false;
        }
        
        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy stopped.\n");
    }

}