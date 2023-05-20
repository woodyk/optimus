<p align="center"><img src="https://raw.githubusercontent.com/woodyk/optimus/main/web/assets/img/optimus-banner.png" alt="Optimus Banner"></p>

---

![Built With PERL](https://img.shields.io/badge/built%20with-PERL-blue) ![Built With Docker](https://img.shields.io/badge/built%20with-Docker-blue) ![Built With Elasticsearch](https://img.shields.io/badge/built%20with-Elasticsearch-green) ![Built With Kibana](https://img.shields.io/badge/built%20with-Kibana-ff69b4) ![Built With BASH](https://img.shields.io/badge/built%20with-BASH-2d3b3e) ![Built With PHP](https://img.shields.io/badge/built%20with-PHP-7b86b9)

## About

Optimus is a simple network packet indexer for Elasticsearch.

Tools such as tshark proved to be more than I needed.  Optimus simplifies the task of indexing the most used protocols into Elasticsearch.  Capable of live network sampling or importing of pcaps.  Optimus can have you quickly indexing, and searching your network information with tools such as Kibana or Grafana.  Optimus is not meant for 100% continuous network packet collection.  Instead, the idea is to gather enough packets to enable quick, easy, and accurate research of your traffic.

---

## Current Status

> **Note** This project is currently under early development and there are no guarantees of functionality.

---

## Features

### Overview
- Indexes network traffic to Elasticsearch.
- Visualize your data with tools such as Kibana or Grafana.
- Enriches your traffic data with reverse DNS, HTTP headers, GeoIP, and MAC vendor details.
- Capable of live traffic sampling or importing of pcaps.
- Simple web API for processing pcap data.  Only supports JSON output at the moment.
- Provides JSON output for use with your own applications.
- Creates Elasticsearch template mappings, index policy, and GeoIP injest pipelines.

### Supported Protocol Recognition

| Protocol | OSI Layer |
| :--- | :---: |
| `Ethernet` | 2 |
| `ARP` | 2 |
| `IP_ROUTE` | 2 |
| `IP` | 3 |
| `IPv6` | 3 |
| `ICMP` | 3 |
| `ICMPv6` | 3 |
| `IGMP` | 3 |
| `TCP` | 4 |
| `UDP` | 4 |
| `HTTP` | 7 |
| `SSL` | 7 |
| `SSH` | 7 |
| `DNS-MDNS` | 7 |
| `NTP` | 7 |

### Supported Elasticsearch Versions

| Elasticsearch | Optimus |
| :---: | :---: |
| 8.x | current |

### Tested Operating Systems

| OS | Version |
| :---: | :---: |
| Ubuntu | 14.04 |
| Ubuntu | 20.04 |
| Ubuntu | 22.04 |
| MacOS | 12.6 |

---

## Installation

### Linux
#### Download

```
git clone https://github.com/woodyk/optimus.git
cd optimus
```

#### Install required packages.

##### Ubuntu
```
sudo apt-get update
sudo apt-get install -y gzip make curl gcc libpcap-dev net-tools libjson-perl libnet-pcap-perl libdata-dmp-perl libsys-hostname-long-perl libgetopt-long-descriptive-perl libuuid-tiny-perl libmaxmind-db-reader-perl libnet-ipaddress-perl libnetpacket-perl libuuid-tiny-perl libmaxmind-db-reader-perl libsearch-elasticsearch-perl
```

##### Manual
```
cpanm -n --installdeps . --force
```

You can test that your modules are installed properly by running.

```
perl -wc bin/optimus.pl
```

> **Note** It should return the following. If not please ensure that all the modules contained within file cpanfile are installed properly.

```
bin/optimus.pl syntax OK
```

#### Preparing Elasticsearch and Kibana

##### Optional Elasticsearch test environment
If you don't have Elasticsearch and Kibana you can spin up docker containers as follows.

```
docker network create elastic
docker run -d --rm --net elastic --name elastic -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" -e "xpack.security.enabled=false" elasticsearch:8.5.2
docker run -d --rm --net elastic --name kibana -p 5601:5601 -e 'ELASTICSEARCH_HOSTS="http://elastic:9200"' kibana:8.5.2
```

##### Prepare Elasticsearch for your data.

```
bin/elasticsearch_setup.sh localhost:9200
```

Optionaly you can setup Kibana with some pre-made visualizations.

```
bin/kibana_setup.sh localhost:5601 lib/examples/elasticsearch_setup/kibana_setup.json
```

> **Note** Ensure that both Elasticsearch and Kibana return success.


After you are finished testing you can clean up with the following.

```
docker stop elastic
docker stop kibana
docker rm elastic
docker rm kibana
docker network rm elastic
```

---

## Running Optimus

### Command Line
Optimus can be run with a few different options.  The following example would be very common. This will run once on interface eth0 for 1000 packets, injecting to Elasticsearch node localhost:9200, saving 1024 bytes of the payload, and processing layer 7 information such as protocol and HTTP headers.

```
bin/optimus.pl -i eth0 -c 1000 --server localhost:9200 --bytes 1024 --l7
```

If you wish to collect samples continuously modify the script run.sh and add the necessary command line switches to the script. Then execute.

> **Note** Replace eth0 with your network interface.

```
./run.sh eth0 &
```

### Docker
#### Prepare Docker Image

You can build the image yourself using the following.

```
docker build -t optimus .
```

Or you can pull the latest docker image from git packages.

```
docker pull ghcr.io/woodyk/optimus
```

#### Docker Run 
Run your continer as follows.  Populate the "OPTIMUS_ARGS" environment variable with the necessary arguments. Please see "Optimus Command Line Options" for more information.  This will run optimus continously, collecting 5000 packets at a time and injecting them into your Elasticsearch node. 

> **Note** If you wish to listen to a parent interface this will only work on Linux.  The docker --net=host functionality does not provide access to the physical interfaces of Windows or MacOs.

```
docker run -d --rm -p --net=host -e OPTIMUS_ARGS='-i eth1 -c 5000 --server <ELASTICSEARCH_HOST>:<PORT> --bytes 1024 --l7' --name=optimus_eth1 optimus
```

---

## Web API 

The web API will take your pcap file and return a JSON document containing the breakdown of each packet.  The API does not currently support injection into Elasticsearch.

### Web Server

First you must configure a webserver that supports php.  Set the document root for your web server to ```optimus/web``` directory. For a quick setup you can use PHPs built-in webserver to serve the API.

```
cd optimus/web
php -S 0.0.0.0:8000
```

If you are using the docker deployment, it includes Apache and PHP pre-configured and exposed on ports 8000 and 4430.

You can deploy an "API only" docker container using the following.

```
docker run -d --rm -p 8000:8000 -p 4430:4430 -e OPTIMUS_ARGS='--dummy' --name=optimus_api optimus
```

### Using the API
There are two ways the web API can be used.

1. Use your browser to navigate to your server and upload pcaps manually. eg: http://localhost:8000
2. Automate tasks by using HTTP POST to upload your pcap.

```
curl -F 'upload=@/path/to/pcap' http://localhost:8000
```

---

## Optimus Command Line Options
```
./optimus.pl [options]
	-c          Number of packets to process.
	--bytes     Number of bytes to collect from the payload. Default: none
	--debug     Output debug information to STDOUT.
	--dummy     Run in dummy mode. No actions taken just run for 120 seconds.
	--geoip     Enable geoip collection.
	--help      This help output.
	-i          Interface to listen to.
	--json      Output JSON array to STDOUT.
	-l          Enable syslog logging.
	--l7        Enable layer 7 data collection.
	-p          Pcap file for reading.
	-r          Enable reverse DNS lookup. (much slower)
	--server    Elastic search server with port. eg: 192.168.1.10:9200
	-t          Label name for your datasource.

Examples:
	Listen to eth0 for 10 packets, output JSON, enable L7, process GeoIP.

	./optimus.pl -i eth0 -c 10 --json --l7 --geoip --bytes 1024

	Read from pcap file and output JSON, enable L7, process GeoIP.

	./optimus.pl -p /path/to/pcap --jason --geoip --l7

	Listen to eth0 for 1000 packets ,inject to elasticsearch, capture
	1024 bytes of payload, process layer7 data.

	./optimus.pl -i eth0 -c 1000 --server 192.168.0.10:9200 --bytes 1024 --l7
```

---

## ToDo

> **Note** Some pie in the sky stuff for future releases.

- [ ]  Add Elasticsearch population functionality to web API.
- [ ]  Add support for alternative databases. Depending on demand.
	- [ ]  OpenSearch
	- [ ]  MySQL
	- [ ]  Solr
- [ ] Add graph db options for mapping network communications.
	- [ ]  Neo4j