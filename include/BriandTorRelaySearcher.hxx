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
#include "BriandTorRelay.hxx"
#include "BriandTorCertificates.hxx"
#include "BriandTorStatistics.hxx"

using namespace std;

namespace Briand {

	/**
	 * This class contains methods to query for a suitable relay.
	 * Actually any request for relay is done via Onionoo service because downloading consensus list from
	 * authorities requires (April 2021) ~2MB space and ESP has poor. In futures more relays will be added
	 * and this will bring to much more space required.
	*/
	class BriandTorRelaySearcher : public BriandESPHeapOptimize {
		private:

		// Linux porting requires little modification
		#if defined(ESP_PLATFORM)
			/** File name for the exit nodes cache */
			const char* NODES_FILE_EXIT = "/spiffs/cache_exit";
			/** File name for the guard nodes cache */
			const char* NODES_FILE_GUARD = "/spiffs/cache_guard";
			/** File name for the middle nodes cache */
			const char* NODES_FILE_MIDDLE = "/spiffs/cache_middle";
		#elif defined(__linux__)
			/** File name for the exit nodes cache */
			const char* NODES_FILE_EXIT = "/tmp/toresp32_cache_exit";
			/** File name for the guard nodes cache */
			const char* NODES_FILE_GUARD = "/tmp/toresp32_cache_guard";
			/** File name for the middle nodes cache */
			const char* NODES_FILE_MIDDLE = "/tmp/toresp32_cache_middle";
		#else
			#error "UNSUPPORTED PLATFORM (ESP32 OR LINUX REQUIRED)"
		#endif

		protected:

		unsigned char skipRandomResults;
		unsigned char randomPick;
		bool cacheValid;

		/**
		 * Method to set random members
		*/
		virtual void randomize();
		
		/**
		 * Method refreshed node cache by downloading a fresh consensus.
		*/
		virtual void RefreshNodesCache();

		/**
		 * Method check the file cache validity.
		 * @return true if ok, false otherwise (or cache not exist or has invalid content)
		*/
		virtual bool CheckCacheFile(const char* filename);

		/**
		 * Method check if the given IPs are in the same family (first 2 octest).
		 * @param first First IP address (ex. "61.62.3.4")
		 * @param second Second IP address (ex. "61.64.4.5")
		 * @return true if in the same family, false otherwise.
		*/
		virtual bool IPsInSameFamily(const string& first, const string& second);

		/**
		 * Method check if a port is listed inside a list of ports.
		 * @param port The port
		 * @param portList A list containing a set of ports separated by comma, includes ranges: 22,80-81,443,1-20,9090
		*/
		virtual bool IsPortListed(const unsigned short& port, const string& portList);

		public:

		static const char* LOGTAG;

		BriandTorRelaySearcher();

		~BriandTorRelaySearcher();

		/**
		 * Search for Guard node, from saved cache (if invalid will re-download)
		 * @return A unique pointer to BriandTorRelay object if success, nullptr if fails.
		*/
		unique_ptr<BriandTorRelay> GetGuardRelay();

		/**
		 * Search for Middle node, from saved cache (if invalid will re-download)
		 * @param avoidGuardIp avoids to choose a middle that is in the same family. Set it empty to allow all (not safe!)
		 * @return A unique pointer to BriandTorRelay object if success, nullptr if fails.
		*/
		unique_ptr<BriandTorRelay> GetMiddleRelay(const string& avoidGuardIp);

		/**
		 * Search for Exit node, from saved cache (if invalid will re-download)
		 * @param avoidGuardIp avoids to choose an exit that is in the same family. Set it empty to allow all (not safe!)
		 * @param avoidMiddleIp avoids to choose an exit that is in the same family. Set it empty to allow all (not safe!)
		 * @return A unique pointer to BriandTorRelay object if success, nullptr if fails.
		*/
		unique_ptr<BriandTorRelay> GetExitRelay(const string& avoidGuardIp, const string& avoidMiddleIp);

		/**
		 * Deletes the current stored cache
		 * @param forceRefresh starts a new download if true
		*/
		void InvalidateCache(bool forceRefresh = false);

		/**
		 * Prints the cache contents to serial output
		*/
		void PrintCacheContents();

		/** Inherited from BriandESPHeapOptimize */
		virtual void PrintObjectSizeInfo();
		/** Inherited from BriandESPHeapOptimize */
		virtual size_t GetObjectSize();
		
	};
}