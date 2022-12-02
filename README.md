# optimus
```
./optimus.pl
	-c	Number of packets to process.
	-b	Number of bytes to collect from the payload. Default: none
	-d	Output debug information to STDOUT.
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

	Read from pcap file and output JSON.

	./optimus.pl -p /path/to/pcap -j

	Listen to eth0 for 1000 packets ,inject to elasticsearch, capture
	1024 bytes of payload, process layer7 data.

	./optimus.pl -i eth0 -c 1000 -s 192.168.0.10:9200 -b 1024 --l7
```

## Prepare elasticsearch for data.
Prepare ElasticSearch for your data.
```
bin/elasticsearch_setup.sh <ES IP ADDRESS>:<PORT>
```
The following should be returned.
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

### Build Docker Images
Once all your changes are made you can execute the following to build a docker instance tuned to your settings and execute it.
```
docker build -t optimus .
```
Run your continer as follows.  Populate the "OPTIMUS_ARGS" environment variable with the necessary arguments. Please see the help output for more information.
```
docker run -d --restart always -p 8000:8000 --net=host -e OPTIMUS_ARGS='-i eth1 -c 5000 -s elasticsearch.server --bytes 1024 --l7' --name=optimus_eth1 optimus
```

### Web API 
#### Web Server
First you must configure a webserver that supports php.  The DOCUMENT_ROOT should be the web directory. For a quick setup you can use the php built-in webserver to serve the API.
```
cd optimus/web
php -S 0.0.0.0:8000
```
If you are using the docker deployment, it includes preconfigured apache and php exposed on ports 8000 and 4430.

You can deploy and API only docker container using the following.
```
docker run -d --rm -p 8000:8000 -p 4430:4430 -e OPTIMUS_ARGS='--dummy' --name=optimus_api optimus
```

#### Using the API
There are two ways the web api can be used.

1. Go to the webserver IP address and upload pcaps using the form. eg: http://localhost:8000
2. POST your pcap using a tool such as curl.
```
curl -F 'upload=@/path/to/pcap' http://localhost:8000
```
