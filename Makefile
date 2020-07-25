all: pcap_test

pcap_test: main.o
	g++ -o pcap_test main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -rf pcap_test *.o
