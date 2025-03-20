for i in /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages; do 
	echo 4096 > $i
done
export RTE_SDK=/usr/local/src/dpdk-stable-18.11.10
export RTE_TARGET=x86_64-native-linuxapp-gcc
