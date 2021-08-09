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

        // Listen for maximum TOR_CIRCUITS_KEEPALIVE connections
        if (listen(this->proxySocket, TOR_CIRCUITS_KEEPALIVE) != 0) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy error on binding.\n");
            close(this->proxySocket);
            this->proxySocket = -1;
            return;
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy listening.\n");

        xTaskCreate(this->HandleRequest, "TorProxy", 2048, reinterpret_cast<void*>(this->proxySocket), 5, &this->proxyTaskHandle);

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
                ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy: null server socket! Closing task.\n");
                vTaskDelete(NULL);
            }
            else {
                // Convert parameter
                int serverSock = (int)serverSocket;

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: accepting connections.\n");

                // Wait a connection
                struct sockaddr_in clientAddr;
                socklen_t clientAddrLen = sizeof(clientAddr);
                int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientAddrLen);

                if (clientSock < 0) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy cannot accept connection.\n");
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy accepted incoming connection from %s\n", BriandUtils::IPv4ToString(clientAddr.sin_addr).c_str());

                // Start task to handle this client
                xTaskCreate(HandleClient, "TorProxyReq", 2048, reinterpret_cast<void*>(clientSock), 6, NULL);
            }

            // Wait before next run
            vTaskDelay(500 / portTICK_PERIOD_MS);
        }
    }

    /* static */ void BriandTorSocks5Proxy::HandleClient(void* clientSocket) {
         // IDF task cannot return
        while (1) {
            if (clientSocket == NULL ||  reinterpret_cast<int>(clientSocket) < 0) {
                //ESP_LOGW(LOGTAG, "[DEBUG] SOCKS5 Proxy HandleClient shutdown (no socket)\n");
                // If clientSocket == -1 then this is the call for terminate this task.
                if (clientSocket != NULL && reinterpret_cast<int>(clientSocket) == -1) {
                    clientSocket = reinterpret_cast<void*>(-2);
                    vTaskDelete(NULL);
                }
                vTaskDelay(500/portTICK_PERIOD_MS);
            }
            else {
                // Convert parameter
                int clientSock = reinterpret_cast<int>(clientSocket);
                //
                // Very good example: https://www.programmersought.com/article/85795017726/
                // 

                ESP_LOGW(LOGTAG, "[DEBUG] SOCKS5 Proxy HandleClient with clientSock = %d\n", clientSock);

                auto recBuf = make_unique<unsigned char[]>(258);
                ssize_t len;

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
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }
                
                if (len < 3) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy methods receiving error: less than 3 bytes. Closing connection.\n");
                    // Close client socket
                    ErrorResponse(clientSock, nullptr, 0);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                if (recBuf[0] != 0x05 || recBuf[1] < 0x01) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: no auth method or wrong socks version. Closing connection.\n");
                    // Write back unsupported version / unsupported method and close
                    unsigned char temp[2] = { 0x05, 0xFF };
                    ErrorResponse(clientSock, temp, 2);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
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
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
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
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                // Only CONNECT supported at the moment
                if (recBuf[1] != 0x01) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: command %02X unsupported. Closing connection.\n", recBuf[1]);
                    // Write back unsupported command and close
                    unsigned char temp[4] = { 0x05, 0x07, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                // Only IPv4 or host supported at the moment
                if (recBuf[3] == 0x04) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: unsupported atyp, must be IPv4 (0x01) or hostname (0x03). Closing connection.\n");
                    // Write back unsupported address type and close
                    unsigned char temp[4] = { 0x05, 0x08, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy finding suitable circuit.\n");

                if (BriandTorSocks5Proxy::torCircuits == nullptr) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: circuits manager not ready. Closing connection.\n");
                    // Write back network unreachable
                    unsigned char temp[4] = { 0x05, 0x03, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                BriandTorCircuit* circuit = BriandTorSocks5Proxy::torCircuits->GetCircuit();

                if (circuit == nullptr) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: no suitable circuit. Closing connection.\n");
                    // Write back network unreachable
                    unsigned char temp[4] = { 0x05, 0x03, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                ESP_LOGD(LOGTAG, "SOCKS5 Proxy using circuit with CircID=0x%08X.\n", circuit->GetCircID());

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

                    connectTo = BriandUtils::IPv4ToString(ip);

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
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                // Connect to the destination (RELAY_BEGIN)

                bool openedStream = circuit->TorStreamStart(connectTo, connectPort);

                if (!openedStream) {
                    // Write back unable to connect (refused) and close
                    unsigned char temp[4] = { 0x05, 0x05, 0x00, 0x01 /* omitted */ };
                    ErrorResponse(clientSock, temp, 4);
                    // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                    clientSocket = reinterpret_cast<void*>(-1);
                    // vTaskDelete will be called by next cycle.
                    continue;
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy connected.\n");

                // Send OK Response to client
                {
                    // version fixed to 0x05, 0x00 = OK, 0x00 (reserved), 0x01 Ipv4, 4 bytes to zero (ip), 2 bytes to zero (port)
                    unsigned char temp[10] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    send(clientSock, temp, 10, 0);
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy streaming data.\n");

                bool torStreamOk = true;
                bool torStreamFinished = false;

                do {
                    // Set the default timeout 
                    struct timeval timeout;
                    bzero(&timeout, sizeof(timeout));
                    timeout.tv_sec = TOR_SOCKS5_PROXY_TIMEOUT_S;

                    // Using select() (more compatible) to check if bytes are available.
                    // If timeout is reached, then close the channel.

                    fd_set filter_read;
                    FD_ZERO(&filter_read);
                    FD_SET(clientSock, &filter_read);

                    // Call a fake recv in order to speed-up select() without waiting for timeout in each case.
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: doing fake recv()\n");
                    recv(clientSock, NULL, 0, MSG_PEEK | MSG_DONTWAIT);

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: doing select()\n");

                    // Check for read readyness until timeout
                    if (select(clientSock+1, &filter_read, NULL, NULL, &timeout) < 0) {
                        ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy timeout: read from client (select() failed). Closing connection\n");
                        break;
                    }

                    // Bytes available
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: select() success.\n");
                    
                    // In order to limit tor cells size, read maximum N bytes (maximum RELAY cell payload length)
                    constexpr unsigned short MAX_FREE_PAYLOAD = 498;
                    recBuf = make_unique<unsigned char[]>(MAX_FREE_PAYLOAD);

                    // Check if more bytes are available before blocking socket!
                    ssize_t bytesAvail = 0;
                    ioctl(clientSock, FIONREAD, &bytesAvail);
                    if (bytesAvail > 0) {
                        len = recv(clientSock, recBuf.get(), MAX_FREE_PAYLOAD, 0);
                    }
                    else {
                        len = 0;
                    }

                    // If zero-sized here (after the select()) the client is disconnected. So close connection
                    if (len == 0) {
                        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: client disconnected. Closing connection\n");
                        break;
                    }
                    else if (len < 0) {
                        ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: read from client error. Closing connection\n");
                        break;
                    }

                    // Otherwise read chunks of data until there are bytes and send through TOR
                    do {
                        // The client sent bytes are to be redirected through TOR
                        auto sendBuf = make_unique<vector<unsigned char>>();

                        sendBuf->insert(sendBuf->begin(), recBuf.get(), recBuf.get() + len);
                        circuit->TorStreamSend(sendBuf, torStreamOk);

                        if (!torStreamOk) {
                            ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: TOR streaming write error. Closing connection\n");
                            break;
                        }

                        // Prepare new buffer and read
                        recBuf.reset();
                        recBuf = make_unique<unsigned char[]>(MAX_FREE_PAYLOAD);

                        // Check if more bytes are available before blocking socket!
                        ssize_t bytesAvail = 0;
                        ioctl(clientSock, FIONREAD, &bytesAvail);
                        if (bytesAvail > 0) {
                            len = recv(clientSock, recBuf.get(), MAX_FREE_PAYLOAD, 0);
                        }
                        else {
                            len = 0;
                        }
                    } while (len > 0);
                    
                    // Reset the used buffer and free memory
                    recBuf.reset();

                    // If a TOR stream error occoured when writing to TOR circuit the client read data, close and exit.
                    if (!torStreamOk) {
                        break;
                    }

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: client data has been fully read. Entering in TOR reading cycle.\n");

                    // If not, read from the TOR the response

                    do {
                        auto torRecBuf = make_unique<vector<unsigned char>>();

                        // A single, good, cell must be received within few seconds (1s?) otherwise this call
                        // could take a very long time and client could timeout 
                        // (maybe data is enough and the client should read and write again back)
                        torStreamOk = circuit->TorStreamRead(torRecBuf, torStreamFinished, TOR_SOCKS5_PROXY_TIMEOUT_S);

                        // Can ignore errors (timeout), see below.
                        // if (!torStreamOk) {
                        //     ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: TOR streaming reading error or timeout. Closing connection\n");
                        //     break;
                        // }

                        // Write the received data back to client
                        if(torStreamOk && torRecBuf->size() > 0) {
                            len = send(clientSock, torRecBuf->data(), torRecBuf->size(), 0);
                            if (len < 0) {
                                ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: writing data back to client failed. Closing connection\n");
                                break;
                            }
                        }
                    } while (torStreamOk && !torStreamFinished);

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: TOR data has been fully read.\n");

                    // Next cycle client read and back will start.
                    // The data stream finish from the satisfied client will led to select() in error at next cycle 
                    // so the socket will be closed.
                }
                while(1);

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: clean-up and closing.\n");

                // Cycle ended, close socket and terminate task after a while.
                if (openedStream) {
                    // Close the TOR stream
                    circuit->TorStreamEnd();
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy Tor stream closed.\n");
                }

                shutdown(clientSock, SHUT_RDWR);
                close(clientSock);
                // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                clientSocket = reinterpret_cast<void*>(-1);
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy client connection closed.");
                // This will be called by next cycle: vTaskDelete(NULL);
            }
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