# sudo modprobe -r kvm_intel kvm_amd kvm

all:
	gcc src/main.c -o server -pthread -lcrypto -O3 -march=native
	gcc src/basic-main.c -o bin/basic-server -pthread -lcrypto -O3 -march=native
	gcc src/amir-experiment/01-main.c -o bin/01-amir-server -pthread -lcrypto -O3 -march=native
	gcc src/amir-experiment/02-main.c -o bin/02-amir-server -pthread -lcrypto -O3 -march=native
	gcc src/arafat-experiment/main.c -o bin/arafat-server -pthread -lcrypto -O3 -march=native
	gcc src/miguel-experiment/main.c -o bin/miguel-server -pthread -lcrypto -O3 -march=native
