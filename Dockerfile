FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install gzip wget cpanminus make gcc libpcap-dev net-tools curl tcpdump -y
RUN apt-get install libjson-perl libnet-pcap-perl libconfig-tiny-perl \
libdata-dmp-perl libsys-hostname-long-perl libgetopt-long-descriptive-perl \
libnet-ipaddress-perl libnetpacket-perl libuuid-tiny-perl libmaxmind-db-reader-perl -y
RUN cpanm -f -n Search::Elasticsearch

WORKDIR /optimus
COPY . . 

ENV PATH "/optimus/bin:$PATH"

CMD ["/optimus/bin/docker_run.sh"]
