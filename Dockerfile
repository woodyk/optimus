#FROM ubuntu:20.04
FROM ubuntu

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install tzdata -y
RUN apt-get install gzip wget cpanminus make gcc libpcap-dev net-tools curl tcpdump -y
RUN apt-get install libjson-perl libnet-pcap-perl \
libdata-dmp-perl libsys-hostname-long-perl libgetopt-long-descriptive-perl \
libuuid-tiny-perl libmaxmind-db-reader-perl libnet-ipaddress-perl libnetpacket-perl libuuid-tiny-perl libmaxmind-db-reader-perl -y
RUN apt-get install php -y
RUN cpanm -f -n Search::Elasticsearch

WORKDIR /optimus
COPY . . 
COPY etc/apache2.conf /etc/apache2/
COPY etc/php.ini /etc/php/8.1/apache2/

ENV PATH "/optimus/bin:$PATH"

CMD ["/optimus/bin/docker_run.sh"]
