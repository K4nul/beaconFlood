LDLIBS += -lpcap

all: beaconFlood

beaconFlood:  CWirelessPacket.o CBeaconFlood.o main.o CWirelessPacket.h CBeaconFlood.h
	g++ -g CWirelessPacket.o CBeaconFlood.o main.o -o $@ -lncurses ${LDLIBS}  

CBeaconFlood.o : CWirelessPacket.h CBeaconFlood.h CBeaconFlood.cpp 
	$(CC) -g -c -o $@ CBeaconFlood.cpp 

CWirelessPacket.o : CWirelessPacket.h CWirelessPacket.cpp  
	$(CC) -g -c -o $@  CWirelessPacket.cpp

main.o: CBeaconFlood.h CWirelessPacket.h main.cpp 
	$(CC) -g -c -o $@ main.cpp



clean:
	rm -f beaconFlood *.o
