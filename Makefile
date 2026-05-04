all:
    mkdir -p build && echo "test" > build/arp-scan
	sudo apt-get update -y && sudo sudo apt-get install -y gcc
	gcc src/arp-scan.c -o ./build/arp-scan		
