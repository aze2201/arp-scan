all:
	rm -rf build
	mkdir -p build
	gcc src/arp-scan.c -o build/arp-scan

clean:
	rm -rf build
