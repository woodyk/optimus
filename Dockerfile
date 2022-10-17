FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install openssh-client vim make gcc libpcap-dev net-tools curl tcpdump -y
RUN apt-get install wget libjson-perl libnet-pcap-perl libconfig-tiny-perl \
libdata-dmp-perl libsys-hostname-long-perl libgetopt-long-descriptive-perl \
libnet-ipaddress-perl libnetpacket-perl libsearch-elasticsearch-perl \
libuuid-tiny-perl libmaxmind-db-reader-perl -y

WORKDIR /optimus
COPY . . 

ENV PATH "/optimus/bin:$PATH"

CMD ["/optimus/bin/run_1.sh"]

