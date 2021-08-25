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

#include "BriandTorCircuitsManager.hxx"
#include "BriandUtils.hxx"

using namespace std;

namespace Briand
{
    const char* BriandTorCircuitsManager::LOGTAG = "briandcircmgr";

    unique_ptr<unique_ptr<BriandTorThreadSafeCircuit>[]> BriandTorCircuitsManager::CIRCUITS = nullptr;
    unsigned short BriandTorCircuitsManager::CIRCUIT_POOL_SIZE = 3;
    unsigned short BriandTorCircuitsManager::CIRCUIT_MAX_TIME = 900;
    unsigned short BriandTorCircuitsManager::CIRCUIT_MAX_REQUESTS = 15;
    bool BriandTorCircuitsManager::isStopped = true;

    BriandTorCircuitsManager::BriandTorCircuitsManager() : BriandTorCircuitsManager(3, 15*60, 15) {
    }

    BriandTorCircuitsManager::BriandTorCircuitsManager(const unsigned short& poolSize, const unsigned short& maxTime, const unsigned short& maxRequests) {
        this->CIRCUIT_POOL_SIZE = poolSize;
        this->CIRCUIT_MAX_TIME = maxTime;
        this->CIRCUIT_MAX_REQUESTS = maxRequests;
        this->CIRCUITS = make_unique<unique_ptr<BriandTorThreadSafeCircuit>[]>(this->CIRCUIT_POOL_SIZE);

        // Allocate all thread safe wrappers
        for (unsigned short i=0; i<this->CIRCUIT_POOL_SIZE; i++)
            this->CIRCUITS[i] = make_unique<BriandTorThreadSafeCircuit>();

        this->CIRCUIT_LAST_USED = -1;
        this->isStopped = true;
    }

    BriandTorCircuitsManager::~BriandTorCircuitsManager() {
        this->Stop();
        this->CIRCUITS.reset();
    }

    void BriandTorCircuitsManager::Start() {
        // If not empty, clear out the current circuit pool (useful if Stop() not called and want to re-Start the manager)
        #if !SUPPRESSDEBUGLOG
        ESP_LOGD(LOGTAG, "Stopping old instances.\n");
        #endif

        this->Stop();

        #if !SUPPRESSDEBUGLOG
        ESP_LOGD(LOGTAG, "Starting circuits.\n");
        #endif

        this->isStopped = false;

        // Create a task to periodically check circuit instances situation
        auto pcfg = esp_pthread_get_default_config();
        pcfg.thread_name = "MgrInst";
        pcfg.stack_size = STACK_MgrInst;
        pcfg.prio = 500;
        esp_pthread_set_cfg(&pcfg);
        std::thread t(CircuitsTaskSingle, (void*)NULL);
        t.detach();
    }

    /*static*/ void BriandTorCircuitsManager::CircuitsTaskSingle(void* noparam) {
        // PTHREAD IMPLEMENTATION
        while(!BriandTorCircuitsManager::isStopped && !BriandTorRelaySearcher::CACHE_REBUILDING) {

            #if !SUPPRESSDEBUGLOG
            ESP_LOGD(LOGTAG, "[DEBUG] CircuitsManager main task invoked, checking for instances to be created.\n");
            #endif

            // Check if there are the number of needed circuits built, if not add the needed
            for (unsigned short i = 0; i < BriandTorCircuitsManager::CIRCUIT_POOL_SIZE; i++) {
                // A new circuit to be instanced?
                if (BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance == nullptr) {
                    
                    #if !SUPPRESSDEBUGLOG
                    ESP_LOGD(LOGTAG, "[DEBUG] Adding a new circuit to pool as #%hu.\n", i);
                    #endif

                    BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance = make_unique<BriandTorCircuit>();
                    BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->internalID = i;
                }
                
                // Lock circuit
                unique_lock<mutex> lock(BriandTorCircuitsManager::CIRCUITS[i]->CircuitMutex);

                // Circuit to build?
                if (
                    !BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::BUILT) && 
                    !BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::BUILDING)) 
                {
                    // A new circuit to be built
                    #if !SUPPRESSDEBUGLOG
                    ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu needs to be built, building.\n", i);
                    #endif

                    // Here circuit is not built nor in creating, so build it. 
                    if (!BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->BuildCircuit(false)) {
                        // If fails, reset and terminate.
                        BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance.reset();
                    }
                }
                // A circuit that should be deleted?
                else if (BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::CLOSED)) {
                   
                    #if !SUPPRESSDEBUGLOG
                    ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu is closed, removing from pool.\n", i);
                    #endif

                    // Reset the pointer
                    BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance.reset();
                }   
                // Operative circuit?
                else if(BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::BUILT)) {
                    if (BriandUtils::GetUnixTime() >= BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->GetCreatedOn() + BriandTorCircuitsManager::CIRCUIT_MAX_TIME) {
                        // The circuit should be closed for elapsed time
                        
                        #if !SUPPRESSDEBUGLOG
                        ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu has reached maximum life time, sending destroy.\n", i);
                        #endif
                        
                        BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->TearDown(Briand::BriandTorDestroyReason::FINISHED);
                    }
                    else if (BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->GetCurrentStreamID() >= BriandTorCircuitsManager::CIRCUIT_MAX_REQUESTS) {
                        // The circuit should be closed for maximum requests
                        
                        #if !SUPPRESSDEBUGLOG
                        ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu has reached maximum requests, sending destroy.\n", i);
                        #endif
                        
                        BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->TearDown(Briand::BriandTorDestroyReason::FINISHED);
                    }
                    else if (!BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::STREAMING)) {
                        // No problems                     
                        // Send a PADDING to keep alive!
                        
                        #if !SUPPRESSDEBUGLOG
                        ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu is alive and not busy, sending PADDING.\n", i);
                        #endif

                        BriandTorCircuitsManager::CIRCUITS[i]->CircuitInstance->SendPadding();
                    }
                }
            }
            
            // Wait before next execution.
            vTaskDelay(BriandTorCircuitsManager::TASK_WAIT_BEFORE_NEXT / portTICK_PERIOD_MS);
        }

        #if !SUPPRESSDEBUGLOG
        ESP_LOGD(LOGTAG, "[DEBUG] Stopping CircuitsManager main task.\n");
        #endif
        
    }

    void BriandTorCircuitsManager::Stop() {
        // Kill all circuits, check are not doing work before killing
        
        // This grants no instances are created by instance task while closing the existing ones
        this->isStopped = true;

        unsigned short queue;
        do {
            queue = this->CIRCUIT_POOL_SIZE;

            for (unsigned short i=0; i<this->CIRCUIT_POOL_SIZE; i++) {
                // Lock the circuit
                unique_lock<mutex> lock(this->CIRCUITS[i]->CircuitMutex);

                if (this->CIRCUITS[i]->CircuitInstance != nullptr) {
                    this->CIRCUITS[i]->CircuitInstance.reset();
                }
                else if (this->CIRCUITS[i]->CircuitInstance == nullptr) {
                    queue--;
                }
            }

            // Little delay to prevent wdt reset on ESP32
            vTaskDelay(200 / portTICK_PERIOD_MS);
        } while (queue > 0);
    }

    BriandTorThreadSafeCircuit* BriandTorCircuitsManager::GetCircuit() {
        unsigned short testedCircuits = (this->CIRCUIT_LAST_USED + 1) % this->CIRCUIT_POOL_SIZE;

        do {
            // Evaluate all circuits, including the last used if it is the only one available

            if (BriandTorCircuitsManager::CIRCUITS[testedCircuits]->CircuitInstance != nullptr) {
                auto& circuit = BriandTorCircuitsManager::CIRCUITS[testedCircuits]->CircuitInstance;
                if (circuit->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::BUILT) && 
                    !circuit->StatusGetFlag(BriandTorCircuit::CircuitStatusFlag::STREAMING)) 
                {
                    this->CIRCUIT_LAST_USED = circuit->internalID;
                    return BriandTorCircuitsManager::CIRCUITS[testedCircuits].get();
                }
            }

            testedCircuits = (testedCircuits + 1) % this->CIRCUIT_POOL_SIZE;

        } while (testedCircuits != ((this->CIRCUIT_LAST_USED + 1) % this->CIRCUIT_POOL_SIZE));

        return nullptr;
    }

    bool BriandTorCircuitsManager::IsStarted() {
        return !this->isStopped;
    }

    void BriandTorCircuitsManager::PrintCircuitsInfo() {
        printf("#\tCircID\t\tStatus\t\t\t\t\tPaddings\tCreatedOn\tDescription\n");
        for (unsigned short i=0; i<this->CIRCUIT_POOL_SIZE; i++) {
            printf("%u\t", i);
            if (this->CIRCUITS[i]->CircuitInstance == nullptr) {
                printf("0x00000000\tNONE\t\t\t\t\t%08lu\t%08lu\tNot instanced\n", 0L, 0L);
            }
            else {
                auto& circuit = this->CIRCUITS[i]->CircuitInstance;

                printf("0x%08X\t", circuit->GetCircID());

                string circuitStatus = circuit->StatusGetString();

                /* 
                    Prepend mutex lock information:
                    try to lock, if success then the circuit were free of locks and could be unlocked.
                    If not, then a thread is currently using mutex. Warning: this can be done because
                    calling thread should be a non-blocking thread (ex. statistical/prompt etc.). If would
                    be the same thread then this call will throw system_error. That's why of try-catch
                */
                try {
                    if (this->CIRCUITS[i]->CircuitMutex.try_lock()) {
                        this->CIRCUITS[i]->CircuitMutex.unlock();
                        // nothing else to do
                    }
                    else {
                        circuitStatus = "LCK," + circuitStatus;
                    }
                } catch(...) {
                    ESP_LOGE(LOGTAG, "[WARN] try_lock exception: do not call PrintCircuitsInfo() from a circuit-blocking thread!\n");
                }

                // Indent
                while(circuitStatus.length() < 40) circuitStatus.push_back(' ');

                printf("%s", circuitStatus.c_str());

                printf("%08lu\t", circuit->GetSentPadding());
                printf("%08lu\t", circuit->GetCreatedOn());

                printf("You, ");

                if (circuit->guardNode != nullptr && circuit->guardNode->nickname != nullptr)
                    printf("%s, ", circuit->guardNode->nickname->c_str() );
                
                if (circuit->middleNode != nullptr && circuit->middleNode->nickname != nullptr)
                    printf("%s, ", circuit->middleNode->nickname->c_str() );

                if (circuit->exitNode != nullptr && circuit->exitNode->nickname != nullptr) {
                    printf("%s, ", circuit->exitNode->nickname->c_str() );
                    printf("THE WEB");
                }

                printf("\n");
            }
        }
    }

}