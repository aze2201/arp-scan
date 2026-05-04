all:
    mkdir -p build && echo "test" > build/arp-scan
	sudo apt-get update && apt-get install build-essentials
	gcc src/arp-scan.c -o ./build/arp-scan		
