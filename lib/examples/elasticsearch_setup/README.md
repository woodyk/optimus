# Spin up Elasticsearch and Kibana in docker.

## Elasticsearch

docker run -d --rm --name elastic_optimus -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" -e "xpack.security.enabled=false" elasticsearch:8.5.2

## Kibana
docker run -d --rm --name kibana_optimus -p 5601:5601 -e 'ELASTICSEARCH_HOSTS="http://<IP_OF_PARENT>:9200"' kibana:8.5.2

Allow time for both elasticsearch and kibana to init.
Use docker logs <container name> to view status

Follow the Optimus Installation Steps
Run optimus pointing --server to your new elastic_optimus container.

cd optimus/lib/examples
curl -F 'file=@../lib/examples/kibana_optimus_example.ndjson' -H "kbn-xsrf: true" http://dockermanager.vm.sr:5602/api/saved_objects/_import

# Kibana Example
Browse to http://localhost:5601
Management -> Stack Management
	Saved Objects
		Import
			Choose the optimus/lib/examples/kibana_example.ndjson file.
				click: Import
					click: Done

# Manual Kibana Index Configuration
Management -> Stack Management
        Data Views
                click: Create data view
                        Name: packets_*
                        Index pattern: packets_*
                        Timestamp field: date
                                click: Save data view to Kibana

# Browse your data.
Analytics -> Discover
        Make sure that packets_* is set as the index filter.

