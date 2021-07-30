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

#include <iostream>
#include <memory>
#include <vector>

#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>

#include "BriandDefines.hxx"
#include "BriandTorCircuit.hxx"
#include "BriandTorCircuitsManager.hxx"

using namespace std;

namespace Briand
{
	/** This class provides a SOCKS5 Proxy using tor circuit */
	class BriandTorSocks5Proxy {
        protected:

        /** Proxy server socket */
        int proxySocket;

        /** IDF vTask handle */
        TaskHandle_t proxyTaskHandle;

        /** Pointer to CircuitsManager instance */
        static BriandTorCircuitsManager* torCircuits;

        /**
         * Handles a single request to this proxy
        */
        static void HandleRequest(void* serverSocket);

        /**
         * Method sends an error response and close client connection
         * @param socket Client socket (will be closed!)
         * @param data Data to be sent (NULL if just socket closing is required)
         * @param dataLen Length of data
        */
        static void ErrorResponse(int socket, unsigned char* data, unsigned int dataLen);

        public:

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
        
    };
}