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

#pragma once

#include "BriandDefines.hxx"
#include "BriandTorCircuit.hxx"
#include "BriandTorCircuitsManager.hxx"
#include "BriandNet.hxx"
#include "BriandTorStatistics.hxx"

using namespace std;

namespace Briand
{
	/** This class provides a SOCKS5 Proxy using tor circuit */
	class BriandTorSocks5Proxy {
        protected:

        class StreamWorkerParams {
            public:
            /** The connected client socket */
            int clientSocket;
            /** Reference to the circuit chosen */
            BriandTorThreadSafeCircuit* circuit;
            /** If true, there is nothing more to read from client */
            bool readerFinished;
            /** If true, there is nothing more to write to client */
            bool writerFinished;
            /** If true, client disconnected. */
            bool clientDisconnected;
            /** If true, a TorStreamEnd() has been done. */
            bool torStreamClosed;

            /** Constructor initializes with default parameters */
            StreamWorkerParams() {
                this->clientSocket = -1;
                this->circuit = NULL;
                this->readerFinished = false;
                this->writerFinished = false;
                this->clientDisconnected = false;
                this->torStreamClosed = false;
            }

            /** Destructor just to check make_shared working as expected */
            ~StreamWorkerParams() {
                #if !SUPPRESSDEBUGLOG
                ESP_LOGD(LOGTAG, "[DEBUG] StreamWorker has been destroyed.\n");
                #endif
            }

            bool GoodForWrite() {
                return (
                    !this->clientDisconnected && 
                    !this->torStreamClosed && 
                    !this->writerFinished && 
                    circuit != NULL && 
                    circuit->CircuitInstance != NULL && 
                    clientSocket != -1 &&
                    BriandTorSocks5Proxy::proxyStarted
                );
            }

            bool GoodForRead() {
                return (
                    !this->clientDisconnected && 
                    !this->torStreamClosed && 
                    !this->readerFinished && 
                    circuit != NULL && 
                    circuit->CircuitInstance != NULL && 
                    clientSocket != -1 &&
                    BriandTorSocks5Proxy::proxyStarted
                );
            }
        };

        /** Proxy server socket */
        int proxySocket;

        /** Port of running proxy */
        unsigned short proxyPort;

        /** Proxy status */
        static bool proxyStarted;

        /** Proxy user */
        static string proxyUser;

        /** Proxy password */
        static string proxyPassword;

        /** Pointer to CircuitsManager instance */
        static BriandTorCircuitsManager* torCircuits;

        /** 
            Maximum payload available for read/write stream operations LESS 5 bytes, in order
            to fit this requirement: To ensure unpredictability, random bytes should be added to at least one
			RELAY_DATA cell within one increment window. In other word, every 100 cells (increment), random bytes should be introduced in at least one cell.
        */
        static const unsigned short MAX_FREE_PAYLOAD = 498 - 5;

        /** Delay in mseconds for stream read/write operations */
        static const unsigned short STREAM_WAIT_MS = 200;

        /** Queue of pending clients to serve (contains client sockfd) */
        static queue<int> REQUEST_QUEUE;

        /** Number of active serving clients */
        static unsigned char CURRENT_ACTIVE_CLIENTS;

        /** Number of MAX requests, limits the call to HandleClient(), fixed to a % of TOR_CIRCUITS_KEEPALIVE */
        static const unsigned char REQUEST_QUEUE_LIMIT = (static_cast<unsigned char>( (TOR_SOCKS5_PROXY_MAX_CONN/100.0)*TOR_CIRCUITS_KEEPALIVE ) > 0 ? static_cast<unsigned char>( (TOR_SOCKS5_PROXY_MAX_CONN/100.0)*TOR_CIRCUITS_KEEPALIVE ) : 1);

        /**
         * Handles a single request to this proxy (accept() and queues the request)
         * @param serverSock the server socket FD (int)
        */
        static void QueueClientRequest(const int serverSock);

        /**
         * Manages the request queue, if acceptable calls HandleClient() to serve next client
         * @param serverSock the server socket FD (int)
        */
        static void DeQueueClientRequest(const int serverSock);

        /**
         * Handles a single client (async)
         * @param clientSock the connected client socket FD (int)
        */
        static void HandleClient(const int clientSock);

        /**
         * std::async future Handles a single client receive -> write to tor (async)
         * @param workerParams shared pointer to an existing instance of the StreamWorkerParams
        */
        static void ProxyClient_AsyncStreamReader(shared_ptr<StreamWorkerParams> swParams);

        /**
         * std::async future Handles a single tor receive -> write to client (async)
         * @param workerParams shared pointer to an existing instance of the StreamWorkerParams
        */
        static void ProxyClient_AsyncStreamWriter(shared_ptr<StreamWorkerParams> swParams);

        /**
         * Method sends an error response and close client connection
         * @param socket Client socket (will be closed!)
         * @param data Data to be sent (NULL if just socket closing is required)
         * @param dataLen Length of data
        */
        static void ErrorResponse(int socket, unsigned char* data, unsigned int dataLen);

        public:

        static const char* LOGTAG;

        BriandTorSocks5Proxy();
        ~BriandTorSocks5Proxy();

        /**
         * Method starts the proxy and listens to the specified port.
         * @param port Port number
         * @param manager The Circuits Manager instance
        */
        void StartProxyServer(const unsigned short& port, unique_ptr<BriandTorCircuitsManager>& mgr);

        /**
         * Method stops the proxy and closes any binding.
        */
        void StopProxyServer();
        
        /**
         * Method to self-test simulating a client that requests on 127.0.0.1 remote IP via APIFY. 
         * Uses TOR network, outputs IP to stdout.
        */
        void SelfTest();

        /**
         * Method prints on stdout the proxy status (including credentials)
        */
        void PrintStatus();

    };
}