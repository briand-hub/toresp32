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

#include "BriandTorCircuit.hxx"

using namespace std;

namespace Briand {

    /**
     * This class handles Tor circuits
    */
    class BriandTorCircuitsManager {
		protected:

        /** Task stack size in bytes, obtained by tests. If too low task will crash! */
        static const unsigned short TASK_STACK_SIZE = 5120;

        /** Task re-execution time, obtained by tests, in milliseconds. */
        static const unsigned short TASK_WAIT_BEFORE_NEXT = 30*1000;

        /** Status of the manager */
        static bool isStopped;

        /** The circuit pool */
        static unique_ptr<unique_ptr<BriandTorCircuit>[]> CIRCUITS;

        /** Last used circuit */
        unsigned short CIRCUIT_LAST_USED;

        /** Circuit pool size (default 3) */
        static unsigned short CIRCUIT_POOL_SIZE;

        /** Maximum time in seconds to keep a circuit active before closing it (default 15 minutes) */
        static unsigned short CIRCUIT_MAX_TIME;

        /** Maximum number of requests to do with the same circuit (default 15 requests) before closing it */
        static unsigned short CIRCUIT_MAX_REQUESTS;

        /**
         * This method is asynchronous and provides operations for a single circuit
         * @param circuitIndex an unsigned short (circuit index in the CIRCUITS vector), void* because of ESP-IDF requirement.
        */
        static void CircuitTask(void* circuitIndex);

        /**
         * Method checks and restarts circuits pool with new instances if any is not instanced. Executes only if property isStopped=false
         * @param noparam set to NULL
        */
        static void RestartCircuits(void* noparam);

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
         * @return Raw pointer to the circuit (BE CAREFUL!!), nullptr if no circuits available
        */
       BriandTorCircuit* GetCircuit();

        /** 
         * 
        */

       /**
        * Prints out the current circuits situation
       */
       void PrintCircuitsInfo();
    };
}
