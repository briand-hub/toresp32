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

using namespace std;

namespace Briand {

    /**
     * This class handles Tor circuits
    */
    class BriandTorCircuitsManager {
		protected:

        /** Task stack size in bytes, obtained by tests. If too low task will crash! */
        static const unsigned short TASK_STACK_SIZE = 5120;

        #if defined(ESP_PLATFORM)
        /** Task re-execution time, obtained by tests, in milliseconds. (ESP, min.30 seconds) */
        static const unsigned short TASK_WAIT_BEFORE_NEXT = 30*1000;
        #else
        /** Task re-execution time, obtained by tests, in milliseconds. (Linux could be less, 5 seconds) */
        static const unsigned short TASK_WAIT_BEFORE_NEXT = 5*1000;
        #endif

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
         * Method checks and restarts circuits pool with new instances if any is not instanced. 
         * It also provides operations for all circuits pool.
         * Executes only if property isStopped=false
         * @param noparam set to NULL
        */
        static void CircuitsTaskSingle(void* noparam);

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
         * Method returns true if is started
         * @return status
        */
        bool IsStarted();

        /**
            * Prints out the current circuits situation
        */
        void PrintCircuitsInfo();
    };
}
