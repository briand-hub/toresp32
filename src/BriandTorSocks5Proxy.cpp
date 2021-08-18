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
    string BriandTorSocks5Proxy::proxyUser = "";
    string BriandTorSocks5Proxy::proxyPassword = "";
    unsigned char BriandTorSocks5Proxy::REQUEST_QUEUE = 0;

    BriandTorSocks5Proxy::BriandTorSocks5Proxy() {
        this->proxySocket = -1;
        this->torCircuits = nullptr;
        this->proxyStarted = false;
        bzero(&this->proxyTaskHandle, sizeof(this->proxyTaskHandle));

        // Create a random username and password
        constexpr unsigned char CRED_SIZE = 8;
        this->proxyUser = "";
        this->proxyPassword = "";
        while (this->proxyUser.length() < CRED_SIZE) {
            // Use only alphanumeric ascii-chars [a-z][A-Z][0-9]

            unsigned char randomChar = BriandUtils::GetRandomByte();
            if ( 
                (randomChar >= 0x30 && randomChar <= 0x39) || 
                (randomChar >= 0x41 && randomChar <= 0x5A) ||
                (randomChar >= 0x61 && randomChar <= 0x7A)
            ) 
            {
                this->proxyUser.push_back(randomChar);
            }
        }
        while (this->proxyPassword.length() < CRED_SIZE) {
            // Use only alphanumeric ascii-chars [a-z][A-Z][0-9]

            unsigned char randomChar = BriandUtils::GetRandomByte();
            if ( 
                (randomChar >= 0x30 && randomChar <= 0x39) || 
                (randomChar >= 0x41 && randomChar <= 0x5A) ||
                (randomChar >= 0x61 && randomChar <= 0x7A)
            ) 
            {
                this->proxyPassword.push_back(randomChar);
            }
        }
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

        // Listen for maximum REQUEST_QUEUE_LIMIT connections
        if (listen(this->proxySocket, REQUEST_QUEUE_LIMIT) != 0) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy error on binding.\n");
            close(this->proxySocket);
            this->proxySocket = -1;
            return;
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy listening.\n");

        xTaskCreate(this->HandleRequest, "TorProxy", 3*1024, reinterpret_cast<void*>(this->proxySocket), 25, &this->proxyTaskHandle);

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

                // Check if this request would be in allowed limits, if not, wait.
                // Limit is defined as REQUEST_QUEUE_LIMIT
                while (REQUEST_QUEUE >= REQUEST_QUEUE_LIMIT) {
                    vTaskDelay(500 / portTICK_PERIOD_MS);
                }

                REQUEST_QUEUE++;

                // Start task to handle this client
                xTaskCreate(HandleClient, "TorProxyReq", 4*1024, reinterpret_cast<void*>(clientSock), 24, NULL);
            }

            // Wait before next run
            vTaskDelay(500 / portTICK_PERIOD_MS);
        }
    }

    /* static */ void BriandTorSocks5Proxy::HandleClient(void* clientSocket) {
         // IDF task cannot return
        while (1) {
            if (clientSocket == NULL ||  reinterpret_cast<int>(clientSocket) < 0) {
                // If clientSocket == -1 then this is the call for terminate this task.
                if (clientSocket != NULL && reinterpret_cast<int>(clientSocket) == -1) {
                    clientSocket = reinterpret_cast<void*>(-2);
                    // Reset the request queue
                    if (REQUEST_QUEUE-1 > 0) REQUEST_QUEUE--;
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

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy HandleClient with clientSock = %d\n", clientSock);

                //auto recBuf = make_unique<unsigned char[]>(258);
                // Moved to static
                unsigned char recBuf[514];

                ssize_t len;

                // Check the first request, should be like 
                // ver |len | methods
                // 0x05|0xNN| NN times methods (max 255)

                len = recv(clientSock, recBuf, 257, 0);

                if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
                    printf("[DEBUG] SOCKS5 Proxy (methods) received %d bytes: ", len);
                    BriandUtils::PrintOldStyleByteBuffer(recBuf, len);
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

                // Find if there is a suitable method (0x00 => no authentication or 0x02 => authentication)
                bool methodOk = false;
                bool useAuthentication = false;
                for (unsigned int i = 2; i<len && i < recBuf[1]+2 ; i++) {
                    if (recBuf[i] == 0x00) {
                        methodOk = true;
                        break;
                    }
                    else if (recBuf[i] == 0x02) {
                        methodOk = true;
                        useAuthentication = true;
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
                if (!useAuthentication) {
                    unsigned char temp[2] = { 0x05, 0x00 };
                    send(clientSock, temp, 2, 0);
                }
                else {
                    unsigned char temp[2] = { 0x05, 0x02 };
                    send(clientSock, temp, 2, 0);
                }

                // Authentication
                if (useAuthentication) {
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy client waiting for auth request.\n");
                    // The client sends an auth request contaning
                    // [version:0x05] [ulen (1byte)] [uname (1-255 bytes)] [plen (1byte)] [passwd (1-255 bytes)]
                    // MAX buffer of 513/514 bytes
                    // Moved to static
                    // recBuf = make_unique<unsigned char[]>(514);
                    bzero(recBuf, 514);
                    len = recv(clientSock, recBuf, 513, 0);

                    if (len < 5) {
                        ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy methods receiving error: less than 5 bytes. Closing connection.\n");
                        // Close client socket
                        ErrorResponse(clientSock, nullptr, 0);
                        // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                        clientSocket = reinterpret_cast<void*>(-1);
                        // vTaskDelete will be called by next cycle.
                        continue;
                    }

                    if (recBuf[0] != 0x05) {
                        ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: wrong socks version on authentication. Closing connection.\n");
                        // Write back unsupported version / unsupported method and close
                        unsigned char temp[2] = { 0x05, 0xFF };
                        ErrorResponse(clientSock, temp, 2);
                        // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                        clientSocket = reinterpret_cast<void*>(-1);
                        // vTaskDelete will be called by next cycle.
                        continue;
                    }

                    string rUser = "";
                    string rPass = "";
                    unsigned short index = 2;
                    while (index < recBuf[1]+2 && index < len) {
                        rUser.push_back(recBuf[index]);
                        index++;
                    }
                    unsigned short pStops = recBuf[index] + index + 1;
                    index++;
                    while (index < pStops && index < len) {
                        rPass.push_back(recBuf[index]);
                        index++;
                    }

                    if (BriandTorSocks5Proxy::proxyUser.compare(rUser) != 0 || BriandTorSocks5Proxy::proxyPassword.compare(rPass) != 0) {
                        ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: wrong credentials. Closing connection.\n");
                        // Write back error
                        unsigned char temp[2] = { 0x05, 0xFF };
                        ErrorResponse(clientSock, temp, 2);
                        // Set the PARAMETER clientSocket to -1 so any other cycle will fail.
                        clientSocket = reinterpret_cast<void*>(-1);
                        // vTaskDelete will be called by next cycle.
                        continue;
                    }

                    // Auth OK to client
                    {
                        unsigned char temp[2] = { 0x05, 0x00 };
                        send(clientSock, temp, 2, 0);
                    }

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy client authenticated.\n");
                }

                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy client waiting for request.\n");

                // At this point client sends a request to connect

                // Moved to static
                //recBuf = make_unique<unsigned char[]>(32);  // request could be max 22 bytes long
                len = recv(clientSock, recBuf, 32, 0);

                if (esp_log_level_get(LOGTAG) == ESP_LOG_DEBUG) {
                    printf("[DEBUG] SOCKS5 Proxy connect request received %d bytes: ", len);
                    BriandUtils::PrintOldStyleByteBuffer(recBuf, len);
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

                BriandTorCircuit* circuit = nullptr; 

                // Keep waiting until one circuit becomes ready, with a timeout.
                unsigned long int stopTimeout = NET_CONNECT_TIMEOUT_S + BriandUtils::GetUnixTime();
                while (BriandUtils::GetUnixTime() < stopTimeout) {
                    circuit = BriandTorSocks5Proxy::torCircuits->GetCircuit();
                    if (circuit != nullptr) break;
                    vTaskDelay(200/portTICK_PERIOD_MS);
                }

                // If still no circuit found after timeout, error.
                if (circuit == nullptr) {
                    ESP_LOGW(LOGTAG, "[WARN] SOCKS5 Proxy error: no suitable circuit found in time. Closing connection.\n");
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

                // Prepare the needed parameter
                auto parameter = make_unique<StreamWorkerParams>();
                parameter->clientSocket = clientSock;
                parameter->circuit = circuit;

                // Start the reader task
                xTaskCreate(ProxyClient_Stream_Reader, "StreamRD", 4*1024, reinterpret_cast<void*>(parameter.get()), 20, NULL);
                // Wait a little (1 second) because client should write us before we write him
                vTaskDelay(1000 / portTICK_PERIOD_MS);
                // Then start the writer task
                xTaskCreate(ProxyClient_Stream_Writer, "StreamWR", 4*1024, reinterpret_cast<void*>(parameter.get()), 20, NULL);

                // Now wait that read/write finished.
                while(!parameter->readerFinished || !parameter->writerFinished) {
                    vTaskDelay(500 / portTICK_PERIOD_MS);
                }

                // Check if the Tor circuit has been closed for stream
                if (!parameter->torStreamClosed) {
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy closing Tor stream.\n");
                    circuit->TorStreamEnd();
                }

                // Check if socket has been closed
                if (parameter->clientSocket > 0) {
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy closing socket.\n");
                    close(clientSock);
                }

                // Set to -1 the clientSocket parameter so this task will be killed
                clientSocket = reinterpret_cast<void*>(-1);
            }
        }
    }

    /* static */ void BriandTorSocks5Proxy::ProxyClient_Stream_Writer(void* swParams) {
        // IDF Task cannot return
        while (1) {
            // If parameter is null then finish
            if (swParams == NULL) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer called with NULL parameter, exiting.\n");
                break;
            } 

            // Extract parameter and verify
            StreamWorkerParams* params = reinterpret_cast<StreamWorkerParams*>(swParams);

            if (params == NULL) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer parameter cast failed, exiting.\n");
                break;
            }

            // Check if everything is good
            if (!params->GoodForWrite()) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer not good for streaming, exiting.\n");
                break;
            }
            
            // Ok! Here we need to read from TOR and write back to client.

            // This Lambda helps to make code easier.
            auto CloseWithError = [&]() {  
                params->writerFinished = true;
                params->circuit->TorStreamEnd();
                params->torStreamClosed = true;
                params->clientDisconnected = true;
                if (!params->readerFinished) {
                    params->readerFinished = true;
                }
                close(params->clientSocket);
                params->clientSocket = -1;
            };

            auto buffer = make_unique<vector<unsigned char>>(); 
            buffer->reserve(514); // reserve some bytes

            // Read from TOR and save the finish status (RELAY_END) on the parameters
            bool torStreamOk = params->circuit->TorStreamRead(buffer, params->writerFinished, TOR_SOCKS5_PROXY_TIMEOUT_S);

            if (!torStreamOk) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer error on Tor streaming, exiting.\n");
                CloseWithError();
                break;
            }

            // If we have something to write back to client, send it
            if (buffer->size() > 0) {
                ssize_t len = send(params->clientSocket, buffer->data(), buffer->size(), 0);
                if (len < 0) {
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer error on writing back to client, exiting.\n");
                    CloseWithError();
                    break;
                }
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer streamed %d bytes from TOR to client.\n", len);
            }

            // Reset now the buffer, this avoids exceptions when task is deleted
            buffer.reset();

            // If the REALAY_END has been received, send ending and exit.
            if (params->writerFinished) {
                params->circuit->TorStreamEnd();
                params->torStreamClosed = true;
                break;
            }

            // Wait before next cycle
            vTaskDelay(STREAM_WAIT_MS / portTICK_PERIOD_MS);
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Writer exited.\n");
        // Kill this task but wait a little in order to free memory
        vTaskDelay(STREAM_WAIT_MS / portTICK_PERIOD_MS);
        vTaskDelete(NULL);
    }

    /* static */ void BriandTorSocks5Proxy::ProxyClient_Stream_Reader(void* swParams) {
        // IDF Task cannot return
        while (1) {
            // If parameter is null then finish
            if (swParams == NULL) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader called with NULL parameter, exiting.\n");
                break;
            } 

            // Extract parameter and verify
            StreamWorkerParams* params = reinterpret_cast<StreamWorkerParams*>(swParams);

            if (params == NULL) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader parameter cast failed, exiting.\n");
                break;
            }

            // Check if everything is good
            if (!params->GoodForRead()) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader not good for streaming, exiting.\n");
                break;
            }
            
            // Ok! Here we need to read from client and write to TOR.
            
            // This Lambda helps to make code easier.
            auto CloseWithError = [&]() {  
                params->readerFinished = true;
                params->clientDisconnected = true;
                if (!params->writerFinished) {
                    params->writerFinished = true;
                    params->circuit->TorStreamEnd();
                    params->torStreamClosed = true;
                }
                close(params->clientSocket);
                params->clientSocket = -1;
            };

            // We read from client with a select() and check timeouts or disconnection.

            // Set the default timeout 
            struct timeval timeout;
            bzero(&timeout, sizeof(timeout));
            timeout.tv_sec = TOR_SOCKS5_PROXY_TIMEOUT_S;

            fd_set filter;
            FD_ZERO(&filter);
            FD_SET(params->clientSocket, &filter);

            ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader select()\n");
            int selectResult = select(params->clientSocket + 1, &filter, NULL, NULL, &timeout);

            if (selectResult < 0) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader select() error, marking all as finished and disconnecting.\n");
                CloseWithError();
                break;
            }
            else if (selectResult == 0) {
                ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader select() timeout, marking as finished.\n");
                params->readerFinished = true;
                break;
            }
            else if (FD_ISSET(params->clientSocket, &filter)) {
                // Client ready to be read
                // Moved to static
                //auto buffer = make_unique<unsigned char[]>(MAX_FREE_PAYLOAD);
                unsigned char buffer[MAX_FREE_PAYLOAD];
                ssize_t len = recv(params->clientSocket, buffer, MAX_FREE_PAYLOAD, 0);

                // If select() succeded but len is 0 then client is disconnected!
                if (len == 0) {
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader client disconnected! Exiting.\n");
                    // CloseWithError();
                    // Stop the reader but not the writer: could have something else to write!
                    // If the client is *really* disonnected, then the send() on the writer will fail.
                    params->readerFinished = true;
                    break;
                }
                else if (len < 0) {
                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader error on receiving from client! Exiting.\n");
                    CloseWithError();
                    break;
                }
                else {
                    bool torStreamOk = true;
                    auto sendBuf = make_unique<vector<unsigned char>>();
                    sendBuf->reserve(514); // reserve some bytes
                    sendBuf->insert(sendBuf->begin(), buffer, buffer + len);
                    params->circuit->TorStreamSend(sendBuf, torStreamOk);
                    // Reset now the buffer, this avoids exceptions when task is deleted
                    sendBuf.reset();

                    if (!torStreamOk) {
                        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader TOR Stream error! Exiting.\n");
                        CloseWithError();
                        break;
                    }

                    ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader streamed %d bytes from client to TOR.\n", len);
                }
            }

            // Wait before next cycle
            vTaskDelay(STREAM_WAIT_MS / portTICK_PERIOD_MS);   
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy: ProxyClient_Stream_Reader exited.");
        // Kill this task but wait a little in order to free memory
        vTaskDelay(STREAM_WAIT_MS / portTICK_PERIOD_MS);
        vTaskDelete(NULL);
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

    void BriandTorSocks5Proxy::SelfTest() {
        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest started.\n");

        auto client = make_unique<BriandIDFSocketClient>();
        client->SetVerbose(false);
        client->SetTimeout(NET_CONNECT_TIMEOUT_S, NET_IO_TIMEOUT_S);
        client->SetReceivingBufferSize(64); // should be enough
        
        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest connecting.\n");
        
        if (!client->Connect("127.0.0.1", TOR_SOCKS5_PROXY_PORT)) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on connecting.\n");
            return;
        }

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest connected. Writing methods request\n");
        
        unique_ptr<vector<unsigned char>> wBuf, rBuf;
        
        wBuf= make_unique<vector<unsigned char>>();
        wBuf->reserve(512); // reserve some bytes

        // request v5 with 1 method (0x00 => no auth)
        wBuf->push_back(0x05); wBuf->push_back(0x01); wBuf->push_back(0x00);
        
        if (!client->WriteData(wBuf)) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on writing methods request. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        wBuf->clear();
    
        rBuf = client->ReadData(true);

        if (rBuf == nullptr || rBuf->size() < 2) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on receiving methods response. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        if (rBuf->at(0) != 0x05 || rBuf->at(1) != 0x00) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest invalid methods response received. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        rBuf.reset();

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest Sending connect request.\n");

        string hostname = "ifconfig.me";
        // request v5 connect to hostname ifconfig.me
        wBuf->push_back(0x05); wBuf->push_back(0x01); wBuf->push_back(0x00); wBuf->push_back(0x03);
        // Hostname: ifconfig.me
        wBuf->push_back(static_cast<unsigned char>(hostname.size())); // len
        for (char& c: hostname) wBuf->push_back(static_cast<unsigned char>(c));
        // Port: 80
        wBuf->push_back(0x00); wBuf->push_back(0x50); 

        if (!client->WriteData(wBuf)) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on writing connect request. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        wBuf->clear();
    
        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest connect request sent.\n");

        rBuf = client->ReadData(true);

        if (rBuf == nullptr || rBuf->size() < 2) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on receiving connect response. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        if (rBuf->at(0) != 0x05 || rBuf->at(1) != 0x00) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest connect request failed. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        rBuf.reset();

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest connected to destination. Sending HTTP/GET request.\n");

        // Prepare the HTTP request, send
        string request("");
		request.append("GET /ip HTTP/1.1\r\n");
		request.append("Host: " + hostname + " \r\n");
		request.append("Connection: close\r\n");
		request.append("\r\n");

		for (char& c: request) wBuf->push_back(static_cast<unsigned char>(c));

        if (!client->WriteData(wBuf)) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on writing HTTP request. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        // Close socket for writing
        // WARNING: USING SHUTDOWN() CAUSES TCP/IP LWIP following error:
        /*
        PC: 0x4008e485: tlsf_free at C:\Users\info\.platformio\packages\framework-espidf\components\heap\heap_tlsf.c line 213
        EXCVADDR: 0x0000000b

        Decoding stack results
        0x4008e482: tlsf_free at C:\Users\info\.platformio\packages\framework-espidf\components\heap\heap_tlsf.c line 213
        0x4008e915: multi_heap_free_impl at C:\Users\info\.platformio\packages\framework-espidf\components\heap\multi_heap.c line 220
        0x4008240a: heap_caps_free at C:\Users\info\.platformio\packages\framework-espidf\components\heap\heap_caps.c line 305
        0x4008ebc9: free at C:\Users\info\.platformio\packages\framework-espidf\components\newlib\heap.c line 46
        0x40104f7f: mem_free at C:\Users\info\.platformio\packages\framework-espidf\components\lwip\lwip\src\core\mem.c line 264
        0x40104fc3: do_memp_free_pool at C:\Users\info\.platformio\packages\framework-espidf\components\lwip\lwip\src\core\memp.c line 383
        0x40104ff7: memp_free at C:\Users\info\.platformio\packages\framework-espidf\components\lwip\lwip\src\core\memp.c line 440
        0x40103afe: tcpip_thread at C:\Users\info\.platformio\packages\framework-espidf\components\lwip\lwip\src\api\tcpip.c line 183
        */
        // shutdown(client->GetSocketDescriptor(), SHUT_WR);

        wBuf.reset(); // no more needed

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest HTTP/GET request sent, waiting response.\n");

        rBuf = client->ReadData(false);
        if (rBuf == nullptr || rBuf->size() == 0) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on receiving HTTP/GET response. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        auto httpResponse = BriandNet::UnsignedCharVectorToString(rBuf, true);

        // Erase till \r\n\r\n
        auto pos = httpResponse->find("\r\n\r\n");

        if (pos == string::npos) {
            ESP_LOGE(LOGTAG, "[ERR] SOCKS5 Proxy SelfTest error on extrating body from HTTP/GET response. Disconnecting.\n");
            client->Disconnect();
            return;
        }

        httpResponse->erase(0, pos+4);

        printf("SOCKS5 Proxy had response: %s\n", httpResponse->c_str());
        printf("\n");

        rBuf.reset();

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest Disconnecting.\n");
        
        client->Disconnect();

        ESP_LOGD(LOGTAG, "[DEBUG] SOCKS5 Proxy SelfTest finished.\n");
    }

    void BriandTorSocks5Proxy::PrintStatus() {
        if (this->proxyStarted) {
            printf("PROXY STATUS: started on port %hu\n", TOR_SOCKS5_PROXY_PORT);
            printf("PROXY USERNAME: %s\n", this->proxyUser.c_str());
            printf("PROXY PASSWORD: %s\n", this->proxyPassword.c_str());
        }
        else {
            printf("PROXY STATUS: not started.\n");
        }
    }

}