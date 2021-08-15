# Variables to control Makefile operation
# This files operates smoothly on Platformio project
# Compile with bash make command in the project base directory.

# Min. 8.4.0
MIN_GCC_VERSION = "8.4"
# Path to src/ directory 
SRCPATH = src
# Path to include/ directory
INCLUDEPATH = include
# Path to cJSON component path (IDF Framework or git clone)
# (NO MORE NEEDED) CJSON_PATH = $(IDF_PATH)/components/json/cJSON
# Base Path to LibBriandIDF (with standard platformio.ini should be this path)
BRIAND_LIB_PATH = .pio/libdeps/lolin_d32/LibBriandIDF
# Output executable name
OUTNAME = main_linux_exe
# Compiler g++
CXX = g++
# Flags required
CXXFLAGS = -g -fpermissive -pthread -lmbedtls -lmbedcrypto -lmbedx509 -lsodium -std=gnu++17

#Target main
main:
	# cJSON library is needed, compile from path using Makefile then use .o files generated
	# No more needed
	# make --directory $(CJSON_PATH)

	# Compile project
	# $(CXX) $(CXXFLAGS) -o $(OUTNAME) $(SRCPATH)/*.cpp $(BRIAND_LIB_PATH)/src/*.cpp $(CJSON_PATH)/*.o  -I$(INCLUDEPATH) -I$(CJSON_PATH) -I$(BRIAND_LIB_PATH)/include 
	# New command without cJSON lib
	$(CXX) $(CXXFLAGS) -o $(OUTNAME) $(SRCPATH)/*.cpp $(BRIAND_LIB_PATH)/src/*.cpp -I$(INCLUDEPATH) -I$(BRIAND_LIB_PATH)/include 
