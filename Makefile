# Variables to control Makefile operation
SRCPATH = src/
INCLUDEPATH = include/
CJSON_PATH = 
OUTNAME = main_linux_exe
CC = g++
CFLAGS = -g -fpermissive -pthread -lmbedtls -lmbedcrypto -lsodium -std=gnu++17
main:
	# First compile LibBriandIDF
	# Then cJSON library
	$(CC) -o $(OUTNAME) $(SRCPATH)*.cpp .pio/libdeps/lolin_d32/LibBriandIDF/src/*.cpp  $(CFLAGS) -I$(INCLUDEPATH) -I.pio/libdeps/lolin_d32/LibBriandIDF/include
