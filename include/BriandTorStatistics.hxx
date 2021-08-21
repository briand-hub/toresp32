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
#include "BriandTorCell.hxx"

/* This file contains a class used for TOR statistics */

using namespace std;

namespace Briand {

	/** Static class to manage statistics */
	class BriandTorStatistics {
		public:

		/** Statistics field number of destroy/relay_end/relay_truncate for protocol */
		static unsigned int STAT_NUM_PROTOCOL_ERR;
		/** Statistics field number of destroy/relay_end/relay_truncate for REASON_EXIT_POLICY */
		static unsigned int STAT_NUM_EXIT_POLICY_ERR;
		/** Statistics field number oof good transmissions */
		static unsigned int STAT_NUM_FINISHED;
		/** Statistics field number of PADDING received */
		static unsigned int STAT_NUM_RECV_PADDINGS;
		/** Statistics field for guard node miss in cache */
		static unsigned int STAT_NUM_CACHE_GUARD_MISS;
		/** Statistics field for middle node miss in cache */
		static unsigned int STAT_NUM_CACHE_MIDDLE_MISS;
		/** Statistics field for exit node miss in cache */
		static unsigned int STAT_NUM_CACHE_EXIT_MISS;
		/** Cache time build (s) */
		static unsigned int STAT_CACHE_BUILD_TIME;
		/** No. of dropped node due to same-family ips */
		static unsigned int STAT_NUM_CACHE_SAME_IP_DROP;
		/** Statistics field for guard node connection error */
		static unsigned int STAT_NUM_GUARD_CONN_ERR;
		/** Statistics field for no. of failed CREATE2 */
		static unsigned int STAT_NUM_CREATE2_FAIL;
		/** Statistics field for no. of failed EXTEND2 */
		static unsigned int STAT_NUM_EXTEND2_FAIL;
		/** Max time to build a circuit, milliseconds */
		static unsigned int STAT_BUILD_TIME_MAX;
		/** Max time to send a stream cell through Tor, milliseconds */
		static unsigned int STAT_TOR_SEND_TIME_AVG;
		/** No. of stream cells sent */
		static unsigned int STAT_TOR_SEND_N;
		/** Max time to receive a stream cell from Tor, milliseconds */
		static unsigned int STAT_TOR_RECV_TIME_AVG;
		/** No. of stream cells sent */
		static unsigned int STAT_TOR_RECV_N;

		BriandTorStatistics();
		~BriandTorStatistics();

		/**
		 * Save a statistical information from cell
		*/
		static void SaveStatistic(const unique_ptr<BriandTorCell>& cell);

		/**
		 * Save a statistical information from destroy reason / relay truncated reason
		*/
		static void SaveStatistic(const BriandTorDestroyReason& reason);

		/**
		 * Save a statistical information from a relay end reason
		*/
		static void SaveStatistic(const BriandTorRelayEndReason& reason);

		/**
		 * Print statistics to stdout
		*/
		static void Print();

	};
}