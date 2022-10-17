#FROM perl:5.20
#COPY . /usr/src/myapp
#WORKDIR /usr/src/myapp
#CMD [ "perl", "./your-daemon-or-script.pl" ]


FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install openssh-client vim make gcc libpcap-dev net-tools curl tcpdump -y
RUN apt-get install wget libjson-perl libnet-pcap-perl libconfig-tiny-perl \
libdata-dmp-perl libsys-hostname-long-perl libgetopt-long-descriptive-perl \
libnet-ipaddress-perl libnetpacket-perl libsearch-elasticsearch-perl \
libuuid-tiny-perl libmaxmind-db-reader-perl -y

# cpan install
# UUID::Random




WORKDIR /app
COPY ./app /app

ENV PATH "/app/bin:$PATH"

CMD ["/app/bin/start_test.sh"]

