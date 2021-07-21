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

#include <iostream>
#include <memory>
#include <vector>

using namespace std;

namespace Briand
{
    unique_ptr<unique_ptr<BriandTorCircuit>[]> BriandTorCircuitsManager::CIRCUITS = nullptr;
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
        this->CIRCUITS = make_unique<unique_ptr<BriandTorCircuit>[]>(this->CIRCUIT_POOL_SIZE);
        this->CIRCUIT_LAST_USED = -1;
        this->isStopped = true;
    }

    BriandTorCircuitsManager::~BriandTorCircuitsManager() {
        this->Stop();
        this->CIRCUITS.reset();
    }

    void BriandTorCircuitsManager::Start() {
        // If not empty, clear out the current circuit pool (useful if Stop() not called and want to re-Start the manager)
        ESP_LOGD(LOGTAG, "Stopping old instances.\n");
        this->Stop();
        ESP_LOGD(LOGTAG, "Starting circuits.\n");

        // Create a new object for the allocated pool size.
        for (unsigned short i = 0; i < this->CIRCUIT_POOL_SIZE; i++) {
            this->CIRCUITS[i] = make_unique<BriandTorCircuit>();

            // Save in the internal ID the index in this array
            this->CIRCUITS[i]->internalID = i;

            ESP_LOGD(LOGTAG, "Circuit #%hu instanced. Starting task.\n", i);

            // Start an async build task for each circuit.
            xTaskCreate(this->CircuitTask, "CircuitTask", this->TASK_STACK_SIZE, &(this->CIRCUITS[i]->internalID), 600, NULL);
        }

        this->isStopped = false;

        // Create a task to periodically check circuit instances situation
        xTaskCreate(this->RestartCircuits, "MgrInst", 2048, NULL, 400, NULL);
    }

    /*static*/ void BriandTorCircuitsManager::RestartCircuits(void* noparam) {
        // ESP-IDF task must never return 
        while (1) {
            if (!BriandTorCircuitsManager::isStopped) {
                ESP_LOGE(LOGTAG, "[DEBUG] CircuitsManager main task invoked, checking for instances.\n");

                // Check if there are the number of needed circuits built, if not add the needed
                for (unsigned short i = 0; i < BriandTorCircuitsManager::CIRCUIT_POOL_SIZE; i++) {
                    if (BriandTorCircuitsManager::CIRCUITS[i] == nullptr) {
                        ESP_LOGE(LOGTAG, "[DEBUG] Adding a new circuit to pool as #%hu.\n", i);
                        BriandTorCircuitsManager::CIRCUITS[i] = make_unique<BriandTorCircuit>();
                        BriandTorCircuitsManager::CIRCUITS[i]->internalID = i;
                        xTaskCreate(CircuitTask, "CircuitTask", BriandTorCircuitsManager::TASK_STACK_SIZE, &(BriandTorCircuitsManager::CIRCUITS[i]->internalID), 500, NULL);
                    }
                }
            }
            else {
                ESP_LOGE(LOGTAG, "[DEBUG] Stopping CircuitsManager main task.\n");
                // delete this task
                vTaskDelete(NULL);
            }

            // Wait before next execution.
            vTaskDelay(BriandTorCircuitsManager::TASK_WAIT_BEFORE_NEXT / portTICK_PERIOD_MS);
        }
    }

    /*static*/ void BriandTorCircuitsManager::CircuitTask(void* circuitIndex) {
        // ESP-IDF task must never return 
        while (1) {

            // If this is an "orphan" task of a previous "killed" circuit, terminate.
            if (circuitIndex == NULL || circuitIndex == nullptr) {
                ESP_LOGD(LOGTAG, "[DEBUG] Found orphan circuit, killing task.\n");

                // delete this task!
                vTaskDelete(NULL);
            }
            else {
                unsigned short cIndex = *(reinterpret_cast<unsigned short*>(circuitIndex));

                ESP_LOGD(LOGTAG, "[DEBUG] Invoked task for circuit #%hu.\n", cIndex);

                // If this is an "orphan" task of a previous "killed" circuit, terminate.
                if (cIndex >= BriandTorCircuitsManager::CIRCUIT_POOL_SIZE || BriandTorCircuitsManager::CIRCUITS[cIndex] == nullptr) {
                    ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu is orphan, killing task.\n", cIndex);

                    // delete this task!
                    vTaskDelete(NULL);
                }
                else {
                    auto& circuit = BriandTorCircuitsManager::CIRCUITS[cIndex];
                    
                    if (circuit->IsCircuitCreating()) {
                        // Just wait
                        ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu is creating, waiting.\n", cIndex);
                    }
                    else if (circuit->IsCircuitClosingOrClosed()) {
                        ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu is closing/closed, removing from pool.\n", cIndex);

                        // Reset the pointer
                        BriandTorCircuitsManager::CIRCUITS[cIndex].reset();

                        // Terminate this task
                        vTaskDelete(NULL);
                    }
                    else if (!circuit->IsCircuitBuilt()) {
                        ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu needs to be built, building.\n", cIndex);

                        // Here circuit is not built nor in creating, so build it.
                        if (!circuit->BuildCircuit(false)) {
                            // If circuit fails, reset and terminate.
                            BriandTorCircuitsManager::CIRCUITS[cIndex].reset();
                            vTaskDelete(NULL);
                        }
                    }
                    else if(circuit->IsCircuitBuilt()) {
                        if (BriandUtils::GetUnixTime() >= circuit->GetCreatedOn() + BriandTorCircuitsManager::CIRCUIT_MAX_TIME) {
                            // The circuit should be closed for elapsed time
                            ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu has reached maximum life time, sending destroy.\n", cIndex);
                            circuit->TearDown(Briand::BriandTorDestroyReason::FINISHED);
                        }
                        else if (circuit->GetCurrentStreamID() >= BriandTorCircuitsManager::CIRCUIT_MAX_REQUESTS) {
                            // The circuit should be closed for maximum requests
                            ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu has reached maximum requests, sending destroy.\n", cIndex);
                            circuit->TearDown(Briand::BriandTorDestroyReason::FINISHED);
                        }
                        else if (!circuit->IsCircuitBusy()) {
                            // No problems                     
                            // Send a PADDING to keep alive!
                            ESP_LOGD(LOGTAG, "[DEBUG] Circuit #%hu is alive and not busy, sending PADDING.\n", cIndex);
                            circuit->SendPadding();
                        }
                    }

                    // Wait before next execution.
                    vTaskDelay(BriandTorCircuitsManager::TASK_WAIT_BEFORE_NEXT / portTICK_PERIOD_MS);
                }
            }
        }
    }

    void BriandTorCircuitsManager::Stop() {
        // Kill all circuits
        for (unsigned short i=0; i<this->CIRCUIT_POOL_SIZE; i++) {
            if (this->CIRCUITS[i] != nullptr) {
                this->CIRCUITS[i].reset();
            }
        }

        this->isStopped = true;
    }

    BriandTorCircuit* BriandTorCircuitsManager::GetCircuit() {
        for (unsigned short i = 0; i < BriandTorCircuitsManager::CIRCUIT_POOL_SIZE; i++) {
            if (BriandTorCircuitsManager::CIRCUITS[i] != nullptr) {
                auto& circuit = BriandTorCircuitsManager::CIRCUITS[i];
                if (circuit->IsCircuitBuilt() && !circuit->IsCircuitBusy() && circuit->internalID != this->CIRCUIT_LAST_USED) {
                    this->CIRCUIT_LAST_USED = circuit->internalID;
                    return circuit.get();
                }
            }
        }

        return nullptr;
    }

    void BriandTorCircuitsManager::PrintCircuitsInfo() {
        printf("#\tStatus\t\tPaddings\tCreatedOn\tDescription\n");
        for (unsigned short i=0; i<this->CIRCUIT_POOL_SIZE; i++) {
            printf("%u\t", i);
            if (this->CIRCUITS[i] == nullptr) {
                printf("NONE\t\t%08lu\t%08lu\tNot instanced\n", 0L, 0L);
            }
            else {
                auto& circuit = this->CIRCUITS[i];
                if (circuit->IsCircuitBuilt())
                    printf("Built\t\t");
                else if (circuit->IsCircuitCreating())
                    printf("Building...\t");
                else if (circuit->IsCircuitClosingOrClosed()) 
                    printf("Closing/Closed\t");
                else
                    printf("Unknown\t\t");

                printf("%08lu\t", circuit->GetSentPadding());
                printf("%08lu\t", circuit->GetCreatedOn());

                printf("You <--> ");

                if (circuit->guardNode != nullptr && circuit->guardNode->nickname != nullptr)
                    printf("%s <--> ", circuit->guardNode->nickname->c_str() );
                
                if (circuit->middleNode != nullptr && circuit->middleNode->nickname != nullptr)
                    printf("%s <--> ", circuit->middleNode->nickname->c_str() );

                if (circuit->exitNode != nullptr && circuit->exitNode->nickname != nullptr) {
                    printf("%s <--> ", circuit->exitNode->nickname->c_str() );
                    printf(" THE WEB");
                }
            }
            printf("\n");
        }
    }

}