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

#include "BriandTorCircuit.hxx"

using namespace std;

namespace Briand {

    /**
     * This class handles Tor circuits
    */
    class BriandTorCircuitsManager {
		protected:

        /** The circuit pool */
        static unique_ptr<vector<unique_ptr<BriandTorCircuit>>> CIRCUITS;

        /** The circuit task handle pool */
        static unique_ptr<vector<unique_ptr<TaskHandle_t>>> CIRCUITS_HND;

        /** Last used circuit */
        unsigned short CIRCUIT_LAST_USED;

        /** Circuit pool size (default 3) */
        static unsigned short CIRCUIT_POOL_SIZE;

        /** Maximum time in seconds to keep a circuit active before closing it (default 10 minutes) */
        static unsigned short CIRCUIT_MAX_TIME;

        /** Maximum number of requests to do with the same circuit (default 15 requests) before closing it */
        static unsigned short CIRCUIT_MAX_REQUESTS;

        /**
         * This method is asynchronous and provides operations for a single circuit
         * @param circuitIndex an unsigned short (circuit index), void* because of ESP-IDF requirement.
        */
       static void CircuitTask(void* circuitIndex);

        public:

        /** Constructor */
        BriandTorCircuitsManager();

        /** 
         * Constructor, with specific pool size 
         * @param poolSize The maximum number of circuits to keep built
         * @param maxTime Maximum time in seconds to keep a circuit active before closing it
         * @param maxRequests Maximum number of requests to do with the same circuit before closing it
        */
        BriandTorCircuitsManager(const unsigned short& poolSize, const unsigned short& maxTime, const unsigned short& maxRequests);

        /** Destructor */
        ~BriandTorCircuitsManager();

        /**
         * This method starts all the circuits cycle:
         * Checks the current circuits pool. 
         * Closes circuits used too much or for too long time.
         * Builds new circuits when needed until MAX_POOL_SIZE is reached.
         * Sends PADDING through circuits to keep alive.
        */
        void Start();

        /**
         * This method stops all the circuits cycle, destroys the built ones and perform clean up.
        */
        void Stop();

        /**
         * This method returns a valid circuit to perform requests
         * @return Pointer to the circuit, nullptr if no circuits available
        */
       unique_ptr<BriandTorCircuit> GetCircuit();

       /**
        * Prints out the current circuits situation
       */
       void PrintCircuitsInfo();
    };
}
