#FROM perl:5.20
#COPY . /usr/src/myapp
#WORKDIR /usr/src/myapp
#CMD [ "perl", "./your-daemon-or-script.pl" ]


FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install openssh-server openssh-client vim make gcc libpcap-dev net-tools curl tcpdump -y
RUN apt-get install libgeo-ip-perl libcpanplus-perl libjson-perl libgeo-ip-perl libnet-pcap-perl \
	liblwp-useragent-determined-perl libnet-ipaddress-perl libnet-cidr-lite-perl \
	libnetpacket-perl -y

# Copy NetPacket::IPv6 from app packageee
RUN cpan if UUID::Random 
RUN cpan if Search::Elasticsearch
WORKDIR /app
COPY ./app /app

EXPOSE 22 

ENV PATH "/app/bin:$PATH"

CMD ["/app/bin/start_test.sh"]

