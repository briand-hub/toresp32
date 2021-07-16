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
    unique_ptr<vector<unique_ptr<BriandTorCircuit>>> BriandTorCircuitsManager::CIRCUITS = nullptr;
    unique_ptr<vector<unique_ptr<TaskHandle_t>>> BriandTorCircuitsManager::CIRCUITS_HND = nullptr;
    unsigned short BriandTorCircuitsManager::CIRCUIT_POOL_SIZE = 3;
    unsigned short BriandTorCircuitsManager::CIRCUIT_MAX_TIME = 600;
    unsigned short BriandTorCircuitsManager::CIRCUIT_MAX_REQUESTS = 15;

    BriandTorCircuitsManager::BriandTorCircuitsManager() {
        this->CIRCUIT_POOL_SIZE = 3;
        this->CIRCUIT_MAX_TIME = 10*60;
        this->CIRCUIT_MAX_REQUESTS = 15;
        this->CIRCUITS = make_unique<vector<unique_ptr<BriandTorCircuit>>>();
        this->CIRCUITS_HND = make_unique<vector<unique_ptr<TaskHandle_t>>>();
        this->CIRCUIT_LAST_USED = 0;
    }

    BriandTorCircuitsManager::BriandTorCircuitsManager(const unsigned short& poolSize, const unsigned short& maxTime, const unsigned short& maxRequests) {
        this->CIRCUIT_POOL_SIZE = poolSize;
        this->CIRCUIT_MAX_TIME = maxTime;
        this->CIRCUIT_MAX_REQUESTS = maxRequests;
        this->CIRCUITS = make_unique<vector<unique_ptr<BriandTorCircuit>>>();
        this->CIRCUITS_HND = make_unique<vector<unique_ptr<TaskHandle_t>>>();
        this->CIRCUIT_LAST_USED = 0;
    }

    BriandTorCircuitsManager::~BriandTorCircuitsManager() {
        this->Stop();
        this->CIRCUITS.reset();
    }

    void BriandTorCircuitsManager::Start() {
        // If not empty, clear out the current circuit pool (useful if Stop() not called and want to re-Start the manager)
        if (this->CIRCUITS->size() > 0) {
            if (VERBOSE) printf("[INFO] Current circuit pool is not empty, Stopping and restarting.\n");
            this->Stop();
        }

        // Create a new object for the allocated pool size.
        for (unsigned short i = 0; i < this->CIRCUIT_POOL_SIZE; i++) {
            this->CIRCUITS->push_back(std::move( make_unique<BriandTorCircuit>() ));

            // Start an async build task for each circuit.
            auto curHnd = make_unique<TaskHandle_t>();
            xTaskCreate(this->CircuitTask, "CircuitTask", 4096, &i, 500, curHnd.get());
            this->CIRCUITS_HND->push_back(std::move(curHnd));
        }
    }

    /*static*/ void BriandTorCircuitsManager::CircuitTask(void* circuitIndex) {
        // ESP-IDF task must never return 
        while (1) {
            unsigned short cIndex = *(static_cast<unsigned short*>(circuitIndex));

            if (DEBUG) printf("[DEBUG] Invoked task for circuit #%ud.\n", cIndex);

            auto& circuit = BriandTorCircuitsManager::CIRCUITS->at(cIndex);
            
            if (circuit->IsCircuitCreating()) {
                // Just wait
                if (DEBUG) printf("[DEBUG] Circuit #%ud is creating, waiting.\n", cIndex);
            }
            else if (circuit->IsCircuitClosingOrClosed()) {
                // Get the handler (by moving)
                auto hnd = std::move( BriandTorCircuitsManager::CIRCUITS_HND->at(cIndex) );

                // Remove the handler
                BriandTorCircuitsManager::CIRCUITS_HND->erase(BriandTorCircuitsManager::CIRCUITS_HND->begin() + cIndex);

                // Terminate this task!
                vTaskDelete(*hnd.get());

                // hnd out of scope, automatically destroyed.
            }
            else if (!circuit->IsCircuitBuilt()) {
                // Here circuit is not built nor in creating, so build it.
                circuit->BuildCircuit(false);
            }
            else if(circuit->IsCircuitBuilt()) {
                // Check if the circuit should be closed for elapsed time
                if (circuit->GetCreatedOn() + BriandTorCircuitsManager::CIRCUIT_MAX_TIME >= BriandUtils::GetUnixTime()) {
                    circuit->TearDown(Briand::BriandTorDestroyReason::FINISHED);
                }

                // Check if the circuit should be closed for maximum requests
                if (circuit->GetCurrentStreamID() >= BriandTorCircuitsManager::CIRCUIT_MAX_REQUESTS) {
                    circuit->TearDown(Briand::BriandTorDestroyReason::FINISHED);
                }
            }

            //
            // TODO : check if is convenient to handle here streams requests/commands
            //

            // Check if there are the number of needed circuits built, if not add the needed
            for (unsigned short i = BriandTorCircuitsManager::CIRCUITS->size() - 1; i < BriandTorCircuitsManager::CIRCUIT_POOL_SIZE; i++) {
                BriandTorCircuitsManager::CIRCUITS->push_back(std::move( make_unique<BriandTorCircuit>() ));
                auto curHnd = make_unique<TaskHandle_t>();
                xTaskCreate(CircuitTask, "CircuitTask", 8192, &i, 500, curHnd.get());
                BriandTorCircuitsManager::CIRCUITS_HND->push_back(std::move(curHnd));
            }

            // Wait 10 seconds before next execution.
            vTaskDelay(10000 / portTICK_PERIOD_MS);
        }
    }

    void BriandTorCircuitsManager::Stop() {
        // Terminate any task handle
        for (auto&& thnd : *this->CIRCUITS_HND) {
            vTaskDelete(*thnd.get());
            thnd.reset();
        }

        // Destroy & Reset all circuits
        this->CIRCUITS->clear();
    }

    unique_ptr<BriandTorCircuit> BriandTorCircuitsManager::GetCircuit() {
        return nullptr;
    }

    void BriandTorCircuitsManager::PrintCircuitsInfo() {
        printf("#  Status          Description\n");
        for (unsigned short i=0; i<this->CIRCUIT_POOL_SIZE; i++) {
            printf("%u\t", i);
            if (this->CIRCUITS->size() <= i) {
                printf("NONE\t\tNot instanced\n");
            }
            else {
                auto& circuit = this->CIRCUITS->at(i);
                if (circuit->IsCircuitClosingOrClosed()) 
                    printf("Closing/Closed  ");
                else if (circuit->IsCircuitBuilt())
                    printf("Built           ");
                else if (circuit->IsCircuitCreating())
                    printf("Building...     ");
                else
                    printf("Unknown         ");

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