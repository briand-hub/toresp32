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

#include "BriandTorStatistics.hxx"

using namespace std;

namespace Briand {
	
	unsigned int BriandTorStatistics::STAT_NUM_PROTOCOL_ERR = 0;
	unsigned int BriandTorStatistics::STAT_NUM_EXIT_POLICY_ERR = 0;
	unsigned int BriandTorStatistics::STAT_NUM_FINISHED = 0;
	unsigned int BriandTorStatistics::STAT_NUM_RECV_PADDINGS = 0;
	unsigned int BriandTorStatistics::STAT_NUM_CACHE_GUARD_MISS = 0;
	unsigned int BriandTorStatistics::STAT_NUM_CACHE_MIDDLE_MISS = 0;
	unsigned int BriandTorStatistics::STAT_NUM_CACHE_EXIT_MISS = 0;
	unsigned int BriandTorStatistics::STAT_NUM_GUARD_CONN_ERR = 0;
	unsigned int BriandTorStatistics::STAT_NUM_DESCRIPTOR_FETCH_ERR = 0;
	unsigned int BriandTorStatistics::STAT_NUM_CREATE2_FAIL = 0;
	unsigned int BriandTorStatistics::STAT_NUM_EXTEND2_FAIL = 0;
	unsigned int BriandTorStatistics::STAT_BUILD_TIME_MAX = 0;
	unsigned int BriandTorStatistics::STAT_NUM_CACHE_SAME_IP_DROP = 0;
	unsigned int BriandTorStatistics::STAT_NUM_CACHE_EXIT_PORT_DROP = 0;
	unsigned int BriandTorStatistics::STAT_TOR_SEND_TIME_AVG = 0;
	unsigned int BriandTorStatistics::STAT_TOR_SEND_N = 0;
	unsigned int BriandTorStatistics::STAT_TOR_RECV_TIME_AVG = 0;
	unsigned int BriandTorStatistics::STAT_TOR_RECV_N = 0;
	unsigned int BriandTorStatistics::STAT_CACHE_BUILD_TIME = 0;

	BriandTorStatistics::BriandTorStatistics() { }

	BriandTorStatistics::~BriandTorStatistics() { }

	void BriandTorStatistics::SaveStatistic(const unique_ptr<BriandTorCell>& cell) {
		if (cell->GetCommand() == BriandTorCellCommand::PADDING) {
			BriandTorStatistics::STAT_NUM_RECV_PADDINGS++;
		}
		else if (cell->GetCommand() == BriandTorCellCommand::DESTROY) {
			SaveStatistic(static_cast<BriandTorDestroyReason>(cell->GetPayload()->at(0)));
		}
		else if (cell->GetCommand() == BriandTorCellCommand::RELAY && cell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_TRUNCATED) {
			SaveStatistic(static_cast<BriandTorDestroyReason>(cell->GetPayload()->at(0)));
		}
		else if (cell->GetCommand() == BriandTorCellCommand::RELAY && cell->GetRelayCommand() == BriandTorCellRelayCommand::RELAY_END) {
			SaveStatistic(static_cast<BriandTorRelayEndReason>(cell->GetPayload()->at(0)));			
		}
	}

	void BriandTorStatistics::SaveStatistic(const BriandTorDestroyReason& reason) {
		if (reason == BriandTorDestroyReason::PROTOCOL) {
			BriandTorStatistics::STAT_NUM_PROTOCOL_ERR++;
		}
	}

	void BriandTorStatistics::SaveStatistic(const BriandTorRelayEndReason& reason) {
		if (reason == BriandTorRelayEndReason::REASON_TORPROTOCOL) {
			BriandTorStatistics::STAT_NUM_PROTOCOL_ERR++;
		}
		else if (reason == BriandTorRelayEndReason::REASON_EXITPOLICY) {
			BriandTorStatistics::STAT_NUM_EXIT_POLICY_ERR++;
		}
		else if (reason == BriandTorRelayEndReason::REASON_DONE) {
			BriandTorStatistics::STAT_NUM_FINISHED++;
		}
	}

	void BriandTorStatistics::Print() {
		printf("------ SATISTICS -------\n");

		printf("No. of normal stream finish: %u\n", BriandTorStatistics::STAT_NUM_FINISHED);
		printf("No. of received paddings: %u\n", BriandTorStatistics::STAT_NUM_RECV_PADDINGS);
		printf("No. of exit policy errors: %u\n", BriandTorStatistics::STAT_NUM_EXIT_POLICY_ERR);
		printf("No. of protocol errors: %u\n", BriandTorStatistics::STAT_NUM_PROTOCOL_ERR);
		printf("Cache build time (s): %u\n", BriandTorStatistics::STAT_CACHE_BUILD_TIME);
		printf("No. of cache guard fail: %u\n", BriandTorStatistics::STAT_NUM_CACHE_GUARD_MISS);
		printf("No. of cache middle fail: %u\n", BriandTorStatistics::STAT_NUM_CACHE_MIDDLE_MISS);
		printf("No. of cache exit fail: %u\n", BriandTorStatistics::STAT_NUM_CACHE_EXIT_MISS);
		printf("No. of cache fail for same family ip: %u\n", BriandTorStatistics::STAT_NUM_CACHE_SAME_IP_DROP);
		printf("No. of cache fail for port settings requirements: %u\n", BriandTorStatistics::STAT_NUM_CACHE_EXIT_PORT_DROP);
		printf("No. of failed connections to guard: %u\n", BriandTorStatistics::STAT_NUM_GUARD_CONN_ERR);
		printf("No. of failed descriptor fetch: %u\n", BriandTorStatistics::STAT_NUM_DESCRIPTOR_FETCH_ERR);
		printf("No. of failed create2: %u\n", BriandTorStatistics::STAT_NUM_CREATE2_FAIL);
		printf("No. of failed extend2: %u\n", BriandTorStatistics::STAT_NUM_EXTEND2_FAIL);
		printf("Max time to build a circuit (ms): %u\n", BriandTorStatistics::STAT_BUILD_TIME_MAX);
		printf("Avg time Tor stream recv (ms): %u (based on %u stream cells)\n", BriandTorStatistics::STAT_TOR_RECV_TIME_AVG, BriandTorStatistics::STAT_TOR_RECV_N);
		printf("Avg time Tor stream send (ms): %u (based on %u stream cells)\n", BriandTorStatistics::STAT_TOR_SEND_TIME_AVG, BriandTorStatistics::STAT_TOR_SEND_N);

		printf("------------------------\n");
	}

}