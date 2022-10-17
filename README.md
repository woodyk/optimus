# optimus
```
./optimus.pl
	-i	Interface to listen to.
	-p	Path to pcap file for reading.
	-j	Ouput JSON to STDOUT for each packet.
	-d	Output debug information to STDOUT.
	-c	Number of packets to process. Only works when interface is defined.
	-e	Enable elastic search.
	-s	Elastic search server address with port. eg: 192.168.1.10:9200
	-l	Enable syslog logging.
	-r	Enable reverse DNS lookup. (much slower)
	-h	This help output.

Examples:
	Listen to eth0 for 10 packets and output JSON.
	./optimus.pl -i eth0 -c 10 -j

	Read from pcap file and output JSON.
	./optimus.pl -p /path/to/pcap -j

	Listen to eth0 for 1000 packets and inject data to elasticsearch.
	./optimus.pl -i eth0 -c 1000 -e -s 192.168.0.10:9200
```
