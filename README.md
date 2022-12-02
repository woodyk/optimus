# Optimus
![Built With PERL](https://img.shields.io/badge/built%20with-PERL-blue) ![Built With Docker](https://img.shields.io/badge/built%20with-Docker-blue) ![Built With Elasticsearch](https://img.shields.io/badge/built%20with-Elasticsearch-green) ![Built With Kibana](https://img.shields.io/badge/built%20with-Kibana-ff69b4) ![Built With BASH](https://img.shields.io/badge/built%20with-BASH-2d3b3e) ![Built With PHP](https://img.shields.io/badge/built%20with-PHP-7b86b9)

## About

Optimus is a simple network packet indexer for Elasticsearch.

Tools such as tshark proved to be more than I needed.  Optimus simplifies the task of indexing the most used protocols into Elasticsearch.  Capable of live network sampling or importing of pcaps.  Optimus can have you quickly indexing, and searching your network information with tools such as Kibana.  Optimus is not meant for 100% continuous network packet collection.  Instead, the idea is to gather enough packets to enable quick, easy, and accurate research of your traffic.

---

## Current Status

> **Note** This project is currently under early development and there are no guarantees of functionality.

---

## Features

- Indexes network traffic to Elasticsearch.
- Data ready for tools such as Kibana.
- Enriches your traffic data with reverse DNS, HTTP headers, GeoIP, and MAC vendor details.
- Capable of live traffic sampling or importing of pcaps.
- Simple web API for processing pcap data.  Only supports JSON output at the moment.
- Provides JSON output for use with your own applications.
- Creates Elasticsearch template mappings, index policy, and GeoIP injest pipelines.

---

## Installation

### Linux
#### Download

```
git clone https://github.com/woodyk/optimus.git
```

#### Install required modules.

```
cd optimus
cpanm -n --installdeps . --force
```

You can test that your modules are installed properly by running.
```
perl -wc bin/optimus.pl
```

It should return the folowing. If not please ensure that all the modules contained within file cpanfile are installed properly.
```
bin/optimus.pl syntax OK
```

#### Preparing ElasticSearch

Run the following command.
```
bin/elasticsearch_setup.sh <ES_IP_ADDRESS>:<PORT>
```

The following should be returned from your ElasticSearch node.

```
Creating GeoIP pipeline.
{
  "acknowledged" : true
}
Creating index lifecycle policy.
{
  "acknowledged" : true
}
Creating index template mapping.
{
  "acknowledged" : true
}
```

#### Running Optimus

Optimus can be run with a few different options.  The following example would be very common. This will run once on interface eth0 for 1000 packets, injecting to Elasticsearch node 192.168.0.10:9200, saving 1024 bytes of the payload, and processing layer 7 information such as protocol and HTTP headers.

```
cd bin
./optimus.pl -i eth0 -c 1000 --server 192.168.0.10:9200 --bytes 1024 --l7
```

If you wish to collect samples continuously modify the script run.sh and add the necessary command line switches to the script.  The execute.
```
./run.sh &
```

---

### Docker
#### Build Docker Image

```
docker build -t optimus .
```

#### Run
Run your continer as follows.  Populate the "OPTIMUS_ARGS" environment variable with the necessary arguments. Please see "Optimus Commandline Options" for more information.  This will run optimus continously, collecting 5000 packets at a time and injecting them into your Elasticsearch node. 
```
docker run -d --rm -p 8000:8000 -p 4430:4430 --net=host -e OPTIMUS_ARGS='-i eth1 -c 5000 --server 192.168.0.10:9200 --bytes 1024 --l7' --name=optimus_eth1 optimus
```

---

## Web API 
### Web Server

First you must configure a webserver that supports php.  Set the document root for your web server to optimus/web. For a quick setup you can use PHPs built-in webserver to serve the API.
```
cd optimus/web
php -S 0.0.0.0:8000
```

If you are using the docker deployment, it includes Apache and PHP pre-configured exposed on ports 8000 and 4430.

You can deploy an API only docker container using the following.
```
docker run -d --rm -p 8000:8000 -p 4430:4430 -e OPTIMUS_ARGS='--dummy' --name=optimus_api optimus
```

### Using the API
There are two ways the web API can be used.

1. User your browser to navigate to your server and upload pcaps manually. eg: http://localhost:8000
2. Automate tasks by using HTTP POST to upload your pcap.
```
curl -F 'upload=@/path/to/pcap' http://localhost:8000
```

---

## Optimus Commandline Options
```
./optimus.pl
	-c	Number of packets to process.
	-b	Number of bytes to collect from the payload. Default: none
	--debug	Output debug information to STDOUT.
	--dummy Run in dummy mode. No actions taken just run for 120 seconds.
	-g	Enable geoip collection.
	-h	This help output.
	-i	Interface to listen to.
	-j	Output JSON array to STDOUT.
	-l	Enable syslog logging.
	--l7	Enable layer 7 data collection.
	-p	Path to pcap file for reading.
	-r	Enable reverse DNS lookup. (much slower)
	-s	Elastic search server address with port. eg: 192.168.1.10:9200
	-t	Label name for your datasource.

Examples:
	Listen to eth0 for 10 packets, output JSON, enable L7, process GeoIP.

	./optimus.pl -i eth0 -c 10 -j --l7 -g

	Read from pcap file and output JSON, enable L7, process GeoIP..

	./optimus.pl -p /path/to/pcap -j -g --l7

	Listen to eth0 for 1000 packets ,inject to elasticsearch, capture
	1024 bytes of payload, process layer7 data.

	./optimus.pl -i eth0 -c 1000 --server 192.168.0.10:9200 --bytes 1024 --l7
```
