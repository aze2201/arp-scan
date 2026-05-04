all:
        rm -rf ./build
        mkdir ./build
        sudo apt-get update && sudo apt-get install build-essentials
        gcc src/arp-scan.c -o ./build/arp-scan
