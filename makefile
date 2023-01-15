LDLIBS += -lpcap

all: beaconFlood

beaconFlood: Mac.o WirelessPacket.o CBeaconFlood.o main.o  Mac.h WirelessPacket.h CBeaconFlood.h
	g++ -g Mac.o WirelessPacket.o CBeaconFlood.o main.o -o $@ -lncurses ${LDLIBS}  

Mac.o : Mac.h Mac.cpp 
	g++ -g -c -o $@ Mac.cpp 

WirelessPacket.o : Mac.h WirelessPacket.h WirelessPacket.cpp  
	g++ -g -c -o $@  WirelessPacket.cpp

CBeaconFlood.o : Mac.h WirelessPacket.h CBeaconFlood.h CBeaconFlood.cpp 
	g++ -g -c -o $@ CBeaconFlood.cpp 

main.o: Mac.h CBeaconFlood.h WirelessPacket.h  main.cpp 
	g++ -g -c -o $@ main.cpp

clean:
	rm -f beaconFlood *.o
