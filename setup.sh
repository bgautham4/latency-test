for i in /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages; do 
	echo 4096 > $i
done
export RTE_SDK=/usr/local/src/dpdk
