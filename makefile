LDLIBS += -lpcap

all: beaconFlood

beaconFlood: CMac.o CWirelessPacket.o CBeaconFlood.o main.o  CMac.h CWirelessPacket.h CBeaconFlood.h
	g++ -g CMac.o CWirelessPacket.o CBeaconFlood.o main.o -o $@ -lncurses ${LDLIBS}  

CMac.o : CMac.h CMac.cpp 
	g++ -g -c -o $@ CMac.cpp 

CWirelessPacket.o : CMac.h CWirelessPacket.h CWirelessPacket.cpp  
	g++ -g -c -o $@  CWirelessPacket.cpp

CBeaconFlood.o : CMac.h CWirelessPacket.h CBeaconFlood.h CBeaconFlood.cpp 
	g++ -g -c -o $@ CBeaconFlood.cpp 

main.o: CMac.h CBeaconFlood.h CWirelessPacket.h  main.cpp 
	g++ -g -c -o $@ main.cpp

clean:
	rm -f beaconFlood *.o
