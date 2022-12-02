#!/usr/bin/perl
# Optimus packet to profile transform generator 
# author: woodyk@gmail.com
#
# ipv4 traffic distribution generator and indexer
#

use strict;
use bytes;
use lib '/app/perl5/lib';
use lib '/app/perl5/lib/perl5';
use JSON;
use POSIX;
use Socket;
use Geo::IP;
use Net::Pcap;
use UUID::Random;
use Data::Dumper;
use Sys::Hostname;
use LWP::UserAgent;
use Getopt::Long;
use Net::IPAddress;
use Redis::hiredis;
use Net::CIDR::Lite;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;
use NetPacket::IGMP;
use NetPacket::Ethernet;
use NetPacket::IPv6;
#use Netpacket::ICMPv6;
use Search::Elasticsearch;

$ENV{TZ} = 'UTC';
my $hostname = hostname();

#tcp flags: urg, ack, psh, rst, syn, fin, ece, cwr
my @NetPacketIP = qw( ver hlen flags foffset tos len id ttl proto cksum src_ip dest_ip options data );
my @NetPacketTCP = qw( src_port dest_port seqnum acknum hlen reserved flags winsize cksum urg options data );
my @NetPacketICMP = qw( type code cksum data );
my @NetPacketIGMP = qw( version type len subtype cksum group_addr data );
my @NetPacketUDP = qw( src_port dest_port len cksum data );
my @NetPacketEthernet = qw( src_mac dest_mac type data ); 
my @NetPacketARP = qw( htype proto hlen plen opcode sha spa tha tpa );

# Time to declare your items
my $ref; 				# data container for all the collected samples
my $beanCounter;			# packet counter
my $redis;				# redis handle
my $e;					# elasticsearch handle
my $bulk;				# elasticsearch bulk handle
my $cidr;
my $gi;


#####################################
# Running config options	
#####################################
my $ip6Enable	 = 1;			# Collect IPv6 details
my $l2Enable	 = 1;			# Enable Layer 2 collection details 0=off 1=on.
my $l7Enable	 = 1; 			# Enable Layer 7 collection details 0=off 1=on.
my $quiet	 = 1; 			# Disable JSON to STDOUT 
my $debug	 = 1;			# Enable debugging
my $useRedis	 = 0; 			# Redis On or Off
my $useTags	 = 1;			# Process tag rules
my $geoIp 	 = 1;			# Enable || Disable Geo IP records
my $dataExtended = 0;			# Enable for added detail to be stored about the packets.

#####################################
# Options for writing results to JSON 
#####################################
my $writeFile	= 0;			# Write files out to $fileDir instead of STDOUT
my $filePath	= '/tmp/profiler';	# Path to write files to
my $filePrefix	= 'profiler_';		# prifix for the file names and or elastic index.
my $suffix	= '.json';

#####################################
# ElasticSearch options 
#####################################
my $elastic	= 0;			# use elasticsearch
my $esprefix	= 'profiler_';
my @elNodes	= qw(es1.vm.sr:9200);	# elasticsearch host, and port

#####################################
# Packet Capture options 
#####################################
my $interface	= $ARGV[0]; 		# Set the interface to listen to and profile.
my $payload	= 1;			# Collect payload sample on or off.
my $offset	= 0;			# Starting position to collect the payload.
my $plBits	= 64;			# Number of bits from offset start_position to collect.
my $netFilter	= 0;			# Berkley packet filters to assign to the collection.
my @targetNet	= qw( 192.168.1.0/24 );	# Subnet to to filter for.
my $sample	= 50;			# Packet samples to process.
my $maxPerDest	= 50;			# Max packtes per destination IP to record;
my $offline	= 0;			# Offline mode for pcap file processing
#my $pcapFile	= $ARGV[0];		# File name to be processed
my $pcapFile    = '/dev/null';
chomp($pcapFile);

#####################################
# Overwrite Variables with Environment Settings if they exist.	
#####################################

if ($ENV{OPTIMUS_INTERFACE}) {
	$interface = $ENV{OPTIUMUS_INTERFACE};
}

if ($netFilter == 1) {
	$cidr = Net::CIDR::Lite->new;
	foreach (@targetNet) {
		$cidr->add($_);
	}
}

#####################################
# Open Geo IP handle if enabled. 
#####################################

if ($geoIp == 1) {
	$gi = Geo::IP->open("/usr/share/GeoIP/GeoLiteCity.dat", GEOIP_STANDARD);
}

#####################################
# Sanity checks 
#####################################

# Check that a file has been given if running in offline mode
if ($offline == 1) {
	if (!-e $pcapFile) {
		print "Unable to find file $pcapFile for processing.\n";
		exit 2;
	}
}

if ($useRedis == 1) {
	# Prepare our redis connection
	$redis = Redis::hiredis->new();
	$redis->connect_unix('/var/run/redis/redis.sock');
}

#####################################
# Begin collection of samples.
#####################################
trafSample($interface, $sample);

#####################################
# Process our output 
#####################################
sub output {
        my $epoch = time();
	#my $epochRounded = time() - (time() % 60);
	my $epochRounded = time();
	my $mil = ($epochRounded * 1000);
	my $indexstamp = strftime("%Y.%m.%d.%H", localtime());
	my $indexname = $esprefix.$indexstamp;

	if ($elastic == 1) {
		my $map;
		#$map->{mappings}->{'_default_'}->{dynamic} = 'true';
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{match} = 'http*';
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{match_mapping_type} = 'keyword';
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{mapping}->{index} = 'not_analyzed';
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{mapping}->{type} = 'keyword';

		$map->{mappings}->{'_default_'}->{properties}->{date}->{type} = 'date';
		$map->{mappings}->{'_default_'}->{properties}->{int}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{hostname}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{hostname}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{src_mac}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{dest_mac}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{packets}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tags}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{location}->{type} = 'geo_point';
		$map->{mappings}->{'_default_'}->{properties}->{country_code}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{country_code3}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{country_name}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{region}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{region_name}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{city}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{postal_code}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{latitude}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{longitude}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{time_zone}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{area_code}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{continent_code}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{metro_code}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{ver}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{hlen}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{options}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{cksum}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{foffset}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{tos}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{flags}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{len}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{ttl}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{proto}->{type} = 'keyword';
		# IPv6 specific headers
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{dst}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{src}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{class}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{class}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{nxt}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{hlim}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{flow}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip6}->{properties}->{plen}->{type} = 'long';

		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{data}->{type} = 'keyword';
                $map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{data}->{index} = 'not_analyzed';

                $map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{data}->{type} = 'keyword';
                $map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{data}->{index} = 'not_analyzed';

                $map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{data}->{type} = 'keyword';
                $map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{data}->{index} = 'not_analyzed';

                $map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{data}->{type} = 'keyword';
                $map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{data}->{index} = 'not_analyzed';

		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{src}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{src}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{src}->{index} = 'not_analyzed';

		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{dst}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{dst}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{dst}->{index} = 'not_analyzed';

		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flags}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{SYN}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{FIN}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{ACK}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{ECE}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{URG}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{PSH}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{CWR}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{NS}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{RST}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{dstport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{srcport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{window_size}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{hlen}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{acknum}->{type} = 'long'; 
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{reserved}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{cksum}->{type} = 'long'; 
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{urg}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{options}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{seq}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{srcport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{dstport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{len}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{type}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{code}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{version}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{type}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{len}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{subtype}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{group_addr}->{type} = 'ip';
		# HTTP specific settings
		$map->{mappings}->{'_default_'}->{properties}->{l7}->{properties}->{proto}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{request}->{properties}->{uri}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{request}->{properties}->{uri}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{host}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{host}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"user-agent"}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"user-agent"}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"referer"}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"referer"}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"cookie"}->{type} = 'keyword';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"cookie"}->{index} = 'not_analyzed';

		$e = Search::Elasticsearch->new( nodes => @elNodes );

		unless ($e->indices->exists(index => "$indexname")) {
			my $result = $e->indices->create(
				index => $indexname,
				body  => $map
			);
		}
		$bulk = $e->bulk_helper( max_count => 100,
					 max_time  => 300 );
	}

	my $counter = 0;
	my $result;
	foreach my $key (keys(%{$ref})) {
		my $json = JSON->new();	
		$ref->{$key}->{hostname} = $hostname;
		$ref->{$key}->{int} = $interface;
		my $locaddy;
		$json->indent();
		if ($geoIp == 1) {
			if ($ref->{$key}->{ip}->{ver} == 4) {
				$locaddy = $ref->{$key}->{ip}->{src};
			} elsif ($ref->{$key}->{ip}->{ver} == 6) {
				$locaddy = $ref->{$key}->{ip6}->{src};
			}


			if (my $record = $gi->record_by_addr("$locaddy")) {
				$ref->{$key}->{country_code} = $record->country_code;
				$ref->{$key}->{country_code3} = $record->country_code3;
				$ref->{$key}->{country_name} = $record->country_name;
				$ref->{$key}->{region} = $record->region;
				$ref->{$key}->{region_name} = $record->region_name;
				$ref->{$key}->{city} = $record->city;
				$ref->{$key}->{postal_code} = $record->postal_code;
				$ref->{$key}->{location} = $record->latitude.",".$record->longitude;
				$ref->{$key}->{time_zone} = $record->time_zone;
				$ref->{$key}->{area_code} = $record->area_code; 
				$ref->{$key}->{continent_code} = $record->continent_code;
				$ref->{$key}->{metro_code} = $record->metro_code;
			}
		}
		my $jsonOut = $json->utf8->encode($ref->{$key});
		if ($elastic == 1) {
			$bulk->create({ index 	=> $indexname,
					type  	=> 'pcap_data',
					id	=> $key,
					source	=> $ref->{$key} });
			$counter++;
			if ($debug == 1) {
				print "$counter documents written\n";
			}
		}

		if ($writeFile == 1) {
			open(FO, ">$filePath/$filePrefix$key$epoch$suffix") || die "Unable to open file in $filePath for writing.\n";
				print FO $jsonOut;
			close(FO);
		}
		if ($quiet == 0) {
			#print Dumper $ref->{sum};
			#if ($ref->{$key}->{ip}->{ver} == 6) {
			#	print $jsonOut;
			#}
		}
	}
	if ($elastic == 1) {
		$result = $bulk->flush;
	}
	undef($ref);
	exit(0);
}

#####################################
# Network traffic sampling 
#####################################
sub trafSample {
	my ($dev, $runTime) = @_;
        my $err;
	my $pcap;
	my $filter = "";
	my $filter_compiled;

	# Prepare interface for collection.
	if ($offline == 1) {
        	$pcap = Net::Pcap::open_offline($pcapFile, \$err);
	} else {
        	$pcap = Net::Pcap::open_live($dev, 2048, 1, 0, \$err);
	}
	#$SIG{ALRM} = sub { Net::Pcap::close($pcap); sleep 1; display(); };

        if (!defined($pcap)) {
                warn "Unable to capture traffic on $dev\n";
		exit(1);
        }

        Net::Pcap::compile($pcap, \$filter_compiled, $filter, 0, 0) && warn "Unable to create filter.\n";;

        Net::Pcap::setfilter($pcap, $filter_compiled) && warn "Unable to set filter.\n";
        #alarm $runTime;

        Net::Pcap::loop($pcap, $runTime, \&callout, '');
	Net::Pcap::close($pcap);

	if ($useRedis == 1) {	
		my $error = $redis->get_reply();
	}
	
	output();
}

#####################################
# Network traffic parsing 
#####################################
sub callout {
        my ($user_data, $header, $packet) = @_;

	if ($useRedis == 1) {
		# select profile db instance
		$redis->select(1);
	}

	# ETHERNET declarations
	my ($ether, $l2, $srcMac, $destMac, $l2type);

	# IP declarations
	my ($ip, $ipLen, $ipHlen, $ipCksum, $ipTtl, $ipFoffset, $ipTos, $ipVer, $ipFlags, $ipProto, $ipSrcIp, $ipDstIp, $ipSrcIpInt, $ipDstIpInt, $ipOptions);

	# IPv6 declarations
	my ($ip6, $ip6DstIp, $ip6SrcIp, $ip6Class, $ip6Ver, $ip6Flow, $ip6Plen, $ip6Nxt, $ip6Hlim);

	# TCP delcarations
	my ($tcp, $tcpFlag, $tcpDstPort, $tcpSrcPort, $tcpWinsize, $tcpHlen, $tcpSeq, $tcpAckNum, $tcpReserved, $tcpCksum, $tcpUrg, $tcpOptions);

	# UDP declarations
	my ($udp, $udpSrcPort, $udpDstPort, $udpLen);

	# ICMP declarations
	my ($icmp, $icmpType, $icmpCode, $icmpData);

	# IGMP declarations
	my ($igmp, $igmpVersion, $igmpType, $igmpLen, $igmpSubtype, $igmpGroupAddr, $igmpData);

	# Other declarations for sub callout
	my $state;
	my $packetTime;
	my $mtime;
	my $primaryKey;

	# Set the time to the current minute rounded down to the first second.
	$mtime = time() - (time() % 60);
	$packetTime = strftime("%Y-%m-%dT%H:%M:%S", localtime($header->{tv_sec}));

	# Possible states are UNKNOWN, SUSPECT, CLEAN, DIRTY
	$state = "UNKNOWN";

        $ether		= NetPacket::Ethernet::strip($packet);
        $ip		= NetPacket::IP->decode($ether);

	$ipVer		= $ip->{ver};

	if ($ipVer == 4) {
        	$ipProto	= getprotobynumber($ip->{proto});
		$ipLen		= $ip->{len};
		$ipTtl		= $ip->{ttl};
		$ipHlen		= $ip->{hlen};
		$ipOptions	= $ip->{options};
		$ipDstIp	= $ip->{dest_ip};
		$ipSrcIp	= $ip->{src_ip};
		$ipDstIpInt	= ip2num("$ip->{dest_ip}");
		$ipSrcIpInt	= ip2num("$ip->{src_ip}");
		$ipFoffset	= $ip->{foffset};
		$ipFlags	= $ip->{flags};
		$ipTos		= $ip->{tos};
		$ipCksum	= $ip->{cksum};

		if ($debug == 1) {
			print "$ipSrcIp -> $ipDstIp\n";
			print "\tproto: $ipProto\n";
			print "\tlen: $ipLen\n";
			print "\tttl: $ipTtl\n";
			print "\thlen: $ipHlen\n";
			print "\toptions: $ipOptions\n";
			print "\toffset: $ipFoffset\n";
			print "\tflags: $ipFlags\n";
			print "\ttos: $ipTos\n";
			print "\tversion: $ipVer\n";
			print "\tcksum: $ipCksum\n";
		}
	} elsif ($ipVer == 6 && $ip6Enable == 1) {
  		$ip6 = NetPacket::IPv6->decode($ether);

		$ip6Ver = $ip6->{ver};
		$ip6Class = $ip6->{class};
		$ip6Flow = $ip6->{flow};
		$ip6Plen = $ip6->{plen};
		$ip6Nxt = $ip6->{nxt};
		$ip6Hlim = $ip6->{hlim};
	
		$ip6SrcIp = $ip6->{src_ip};
		$ip6DstIp = $ip6->{dest_ip};
        	$ipProto = getprotobynumber($ip6->{nxt});

		if ($debug == 1) {
			print "$ip6SrcIp -> $ip6DstIp\n";
			print "\tclass: $ip6Class\n";
			print "\tflow: $ip6Flow\n";
			print "\tplen: $ip6Plen\n";
			print "\tnxt: $ip6Nxt $ipProto\n";
			print "\thlim: $ip6Hlim\n";
		}

	}
	
	if ($netFilter == 1) {
		if (!$cidr->find($ipDstIp) && !$cidr->find($ipSrcIp) ) {
                        #print "Required $targetNet not found.\n";
                        return;
                }
        }

	# Primary key that determines indexing resolution.
	$primaryKey = UUID::Random::generate;

	# Only collect N samples perl destination IP;
	$beanCounter->{$ipDstIp}++;
	if ($beanCounter->{$ipDstIp} >= $maxPerDest) {
		return;
	}

	if ($l2Enable == 1) {	
		$l2 = NetPacket::Ethernet->decode($packet);
		$srcMac = $l2->{src_mac};
		$destMac = $l2->{dest_mac};
		$l2type = $l2->{type};
		$ref->{$primaryKey}->{src_mac} = $srcMac;
		$ref->{$primaryKey}->{dest_mac} = $destMac;
		$ref->{$primaryKey}->{type} = $l2type;
	}

	if ($ipVer == 6 && $ip6Enable == 1) {
		$ref->{$primaryKey}->{ip6}->{src}	= $ip6SrcIp;
		$ref->{$primaryKey}->{ip6}->{dst}	= $ip6DstIp;
		$ref->{$primaryKey}->{raw}->{ip}->{src} = $ip6SrcIp;
		$ref->{$primaryKey}->{raw}->{ip}->{dst} = $ip6DstIp;
		$ref->{$primaryKey}->{ip6}->{class}	= $ip6Class;
		$ref->{$primaryKey}->{ip6}->{flow}	= $ip6Flow;
		$ref->{$primaryKey}->{ip6}->{plen}	= $ip6Plen;
		$ref->{$primaryKey}->{ip6}->{nxt}	= $ip6Nxt;
		$ref->{$primaryKey}->{ip6}->{hlim}	= $ip6Hlim;
	}

	if ($ipVer == 4) {
		$ref->{$primaryKey}->{ip}->{dst} = $ipDstIp;
		$ref->{$primaryKey}->{ip}->{src} = $ipSrcIp;
		$ref->{$primaryKey}->{raw}->{ip}->{dst} = $ipDstIp;
		$ref->{$primaryKey}->{raw}->{ip}->{src} = $ipSrcIp;
	}

	$ref->{$primaryKey}->{date} = $packetTime;

	# IPv4 Assignment Tagging
	if ($ipDstIp =~ /\.255$/ || $ipSrcIp =~ /\.255$/) {
		addTag($primaryKey, 'BROADCAST');
	}
	if ($ipDstIp =~ /^22[3-9]|^23[0-9]/ || $ipSrcIp =~ /^22[3-9]|^23[0-9]/ ) { 	#223 - 239 = Multicast
		addTag($primaryKey, 'MULTICAST');
	}

	$ref->{$primaryKey}->{packets}++;
	$ref->{$primaryKey}->{ip}->{ver} = $ipVer;
	$ref->{$primaryKey}->{ip}->{foffset} = $ipFoffset;
	$ref->{$primaryKey}->{ip}->{tos} = $ipTos;
	$ref->{$primaryKey}->{ip}->{flags} = $ipFlags;
	$ref->{$primaryKey}->{ip}->{len} = $ipLen;
	$ref->{$primaryKey}->{ip}->{hlen} = $ipHlen;
	$ref->{$primaryKey}->{ip}->{options} = $ipOptions;
	$ref->{$primaryKey}->{ip}->{ttl} = $ipTtl;
	$ref->{$primaryKey}->{ip}->{proto} = $ipProto;
	$ref->{$primaryKey}->{ip}->{src} = $ipSrcIp;
	$ref->{$primaryKey}->{raw}->{ip}->{src} = $ipSrcIp;
	$ref->{$primaryKey}->{ip}->{cksum} = $ipCksum;

	if ($useRedis == 1) {
		my $stateLabel = uc("META_STATE_$state");
		$redis->append_command("HSET META_IPS|$mtime $ipDstIp");
		$redis->append_command("HINCRBY $ipDstIp|$mtime packets 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.len|$ipLen 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.hlen|$ipHlen 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.cksum|$ipCksum 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.ttl|$ipTtl 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.proto|$ipProto 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.src|$ipSrcIp 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.dst|$ipDstIp 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.flags|$ipFlags 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.foffset|$ipFoffset 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.tos|$ipTos 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.ver|$ipVer 1");
		$redis->append_command("HINCRBY $ipDstIp|$mtime ip.ver|$ipOptions 1");
	}


        if ($ipProto eq "tcp") {
        	$tcp = NetPacket::TCP->decode($ip->{data});
		# TCP flag inspection module
		$ref->{$primaryKey}->{tcp}->{flag}->{FIN} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{SYN} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{RST} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{PSH} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{ACK} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{URG} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{ECE} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{CWR} = "false";
		$ref->{$primaryKey}->{tcp}->{flag}->{NS}  = "false";

        	my @tmp = getFlags($tcp->{flags});
		foreach (@tmp) {
			$ref->{$primaryKey}->{tcp}->{flag}->{$_} = "true";
			$tcpFlag .= "$_:";	
		}
		$tcpFlag =~ s/:$//;
		
		$tcpDstPort	= $tcp->{dest_port};
		$tcpSrcPort	= $tcp->{src_port};
		$tcpWinsize	= $tcp->{winsize};
		$tcpHlen	= $tcp->{hlen};
		$tcpSeq		= $tcp->{seqnum};
		$tcpAckNum	= $tcp->{acknum};
		$tcpReserved	= $tcp->{reserved};
		$tcpCksum	= $tcp->{cksum};
		$tcpUrg		= $tcp->{urg};

		#$tcpOptions	= $tcp->{options};

		$ref->{$primaryKey}->{tcp}->{reserved}		= $tcpReserved;
		$ref->{$primaryKey}->{tcp}->{cksum}		= $tcpCksum;
		$ref->{$primaryKey}->{tcp}->{urg}		= $tcpUrg;
		#$ref->{$primaryKey}->{tcp}->{options}		= $tcpOptions;
		$ref->{$primaryKey}->{tcp}->{acknum}		= $tcpAckNum;
		$ref->{$primaryKey}->{tcp}->{flags}		= $tcpFlag;
		$ref->{$primaryKey}->{tcp}->{hlen}		= $tcpHlen;
		$ref->{$primaryKey}->{tcp}->{dstport}		= $tcpDstPort;
		$ref->{$primaryKey}->{tcp}->{srcport}		= $tcpSrcPort;
		$ref->{$primaryKey}->{tcp}->{seq}		= $tcpSeq;
		$ref->{$primaryKey}->{tcp}->{window_size}	= $tcpWinsize;

		if ($payload == 1) {
			if ($tcp->{data}) {
				$ref->{$primaryKey}->{tcp}->{data} = getClean($tcp->{data});
			}
		}

		if ($useRedis == 1) {
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.flag|$tcp->{flags} 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.dstport|$tcpDstPort 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.srcport|$tcpSrcPort 1");
				#$redis->append_command("HINCRBY $ipDstIp|$state|$mtime tcpSeqNum|$tcpSeq 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.window_size|$tcpWinsize 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.seq|$tcpSeq 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.hlen|$tcpHlen 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.acknum|$tcpAckNum 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.urg|$tcpUrg 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.ckwum|$tcpCksum 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.options|$tcpOptions 1");
				$redis->append_command("HINCRBY $ipDstIp|$mtime tcp.reserved|$tcpReserved 1");
		}
		
		if ($l7Enable == 1) {
			# HTTP inspection module
			if ($tcp->{data} =~ /^GET |^POST |^HEAD |^PUT |^DELETE |^TRACE |^CONNECT /i) {
				my @lines = split("\n", $tcp->{data});
				#print "$lines[0]\n";
				my $methUri = shift(@lines);
				my @methodData = split(" ", $methUri);

				$ref->{$primaryKey}->{l7}->{proto} = 'http';
				$ref->{$primaryKey}->{http}->{request}->{method} = $methodData[0];
				$ref->{$primaryKey}->{http}->{request}->{uri} = $methodData[1];
				$ref->{$primaryKey}->{http}->{request}->{version} = $methodData[2];
				if ($debug == 1) {
					print "layer 7: l7.proto:http http.request method:$methodData[0] uri:$methodData[1] version:$methodData[2]\n";
				}
				if ($dataExtended == 1) {
					$ref->{$primaryKey}->{count}->{l7}->{proto}->{http}++;
					$ref->{$primaryKey}->{count}->{http}->{request}->{method}->{$methodData[0]}++;
					my $byteSize = length($methodData[1]);
					if ($byteSize >= 220) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{220}++;
					} elsif ($byteSize >= 160) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{160}++;
					} elsif ($byteSize >= 80) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{80}++;
					} elsif ($byteSize >= 40) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{40}++;
					} elsif ($byteSize >= 20) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{20}++;
					} elsif ($byteSize >= 10) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{10}++;
					} elsif ($byteSize > 0) {
						$ref->{$primaryKey}->{count}->{l7}->{http}->{request}->{uri}->{bytebucket}->{0}++;
					}
				}

				if ($useRedis == 1) {
					$redis->append_command("HINCRBY $ipDstIp|$state|$mtime l7.proto.http 1");
					$redis->append_command("HINCRBY $ipDstIp|$state|$mtime http.request.method|$methodData[0] 1");
					$redis->append_command("HINCRBY $ipDstIp|$state|$mtime http.request.uri|$methodData[1] 1");
				}	

				foreach (@lines) {
					if ($_ !~ /:/) {
						next;
					}
					my ($header,$headerContent) = split(/: /, $_);
					if ($header !~ /^Accept$|^Accept-Charset$|^Accept-Encoding$|^Accept-Language$|^Accept-Datetime$|^Authorization$|^Cache-Control$|^Connection$|^Cookie$|^Content-Length$|^Content-MD5$|^Content-Type$|^Date$|^Expect$|^From$|^Host$|^If-Match$|^If-Modified-Since$|^If-None-Match$|^If-Range$|^If-Unmodified-Since$|^Max-ForwardsMax-Forwards$|^Origin$|^Pragma$|^Proxy-Authorization$|^Range$|^Referer$|^TE$|^Upgrade$|^User-Agent$|^Via$|^Warning$|^X-Forwarded-For$/i) { next; }					
					if ($header =~ /\r/) {
						next;
					}
					$header = lc($header);
					$header = "$header";
					$headerContent =~ s/^ //;
					$headerContent =~ s/\s+\r$|\r$//;

					$ref->{$primaryKey}->{http}->{header}->{$header} = $headerContent;
					if ($dataExtended == 1) {
						if ($header eq "cookie") {
							my $hrefName = "httpHeader".$header."BucketDist";
							my $byteSize = length($header);
				                        #$ref->{$primaryKey}->{$hrefName};
			        	                if ($byteSize >= 220) {
			                	                $ref->{$primaryKey}->{count}->{$hrefName}->{220}++;
			                        	        $ref->{sum}->{$hrefName}->{220}++;
				                        } elsif ($byteSize >= 160) {
				                                $ref->{$primaryKey}->{count}->{$hrefName}->{160}++;
				                                $ref->{sum}->{$hrefName}->{160}++;
	        			                } elsif ($byteSize >= 80) {
	                			                $ref->{$primaryKey}->{count}->{$hrefName}->{80}++;
	                			                $ref->{sum}->{$hrefName}->{80}++;
	                			        } elsif ($byteSize >= 40) {
	                			                $ref->{$primaryKey}->{count}->{$hrefName}->{40}++;
	                			                $ref->{sum}->{$hrefName}->{40}++;
	                			        } elsif ($byteSize >= 20) {
	                			                $ref->{$primaryKey}->{count}->{$hrefName}->{20}++;
	                			                $ref->{sum}->{$hrefName}->{20}++;
	                			        } elsif ($byteSize >= 10) {
	                			                $ref->{$primaryKey}->{count}->{$hrefName}->{10}++;
	                			                $ref->{sum}->{$hrefName}->{10}++;
	                			        } elsif ($byteSize > 0) {
								$ref->{$primaryKey}->{count}->{$hrefName}->{0}++;
								$ref->{sum}->{count}->{$hrefName}->{0}++;
							}
							next;
						}

						my $hrefName = "httpHeader".$header."Dist";
						#$ref->{$primaryKey}->{$hrefName};
						$ref->{$primaryKey}->{count}->{$hrefName}->{$headerContent}++;
						$ref->{sum}->{$hrefName}->{$headerContent}++;
						if ($useRedis == 1) {
							$redis->append_command("HINCRBY $ipDstIp|$state|$mtime $hrefName|$headerContent 1");
						}
					}
				}
			} elsif ($tcp->{data} =~ /^HTTP\/\d/i) {
                                my @lines = split("\r\n", $tcp->{data});
                                my $responseHeader = shift(@lines);
                                my ($resVersion, $resCode, $resStatus) = split(" ", $responseHeader);
				if ($debug == 1) {
					print "layer 7: l7.proto:http http.response version:$resVersion code:$resCode status:$resStatus\n";
				}
				$ref->{$primaryKey}->{l7}->{proto} = 'http';
				$ref->{$primaryKey}->{http}->{response}->{version} = $resVersion;
				$ref->{$primaryKey}->{http}->{response}->{code} = $resCode;
				$ref->{$primaryKey}->{http}->{response}->{status} = $resStatus;

				foreach (@lines) {
					my $line = $_;
					if ($line !~ /: /) {
						next;
					}

					my ($header,$headerContent) = split(/: /, $line);
					if ($header !~ /^Accept$|^Accept-Charset$|^Accept-Encoding$|^Accept-Language$|^Accept-Datetime$|^Authorization$|^Cache-Control$|^Connection$|^Cookie$|^Content-Length$|^Content-MD5$|^Content-Type$|^Date$|^Expect$|^From$|^Host$|^If-Match$|^If-Modified-Since$|^If-None-Match$|^If-Range$|^If-Unmodified-Since$|^Max-ForwardsMax-Forwards$|^Origin$|^Pragma$|^Proxy-Authorization$|^Range$|^Referer$|^TE$|^Upgrade$|^User-Agent$|^Via$|^Warning$|^X-Forwarded-For$|^X-/i) { next; }
					$header = lc($header);
					$headerContent =~ s/^ //;
					$headerContent =~ s/\s+\r$|\r$//;

				}
			} #elsif ($tcp->{data} =~ /xyz/) { next module for layer 7; }
		}
                #print $ipSrcIp, " ", $ipDstIp, " ", $ipProto, " ", $tmp, " ", $tcp->{data}, "\n"
        } elsif ($ipProto eq "udp") {
        	$udp = NetPacket::UDP->decode($ip->{data});
		$udpDstPort = $udp->{dest_port};
		$udpSrcPort = $udp->{src_port};
		$udpLen	    = $udp->{len};

		$ref->{$primaryKey}->{udp}->{dstport} = $udpDstPort;
		$ref->{$primaryKey}->{udp}->{srcport} = $udpSrcPort;
		$ref->{$primaryKey}->{udp}->{len} = $udpLen;


		if ($payload == 1) {
			if ($udp->{data}) {
				$ref->{$primaryKey}->{udp}->{data} = getClean($udp->{data});
			}
		}
		if ($dataExtended == 1) {
			unless (exists($ref->{$primaryKey}->{count}->{udp}->{dstport}->{$udpDstPort})) {
				push(@{$ref->{$primaryKey}->{udp}->{dstport}}, $udpDstPort);
			}
			$ref->{$primaryKey}->{count}->{udp}->{dstport}->{$udpDstPort}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{udp}->{srcport}->{$udpSrcPort})) {
				push(@{$ref->{$primaryKey}->{udp}->{srcport}}, $udpSrcPort);
			}
			$ref->{$primaryKey}->{count}->{udp}->{srcport}->{$udpSrcPort}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{udp}->{len}->{$udpLen})) {
				push(@{$ref->{$primaryKey}->{udp}->{len}}, $udpLen);
			}
			$ref->{$primaryKey}->{count}->{udp}->{len}->{$udpLen}++;
	
		}
	
	
		if ($useRedis == 1) {
			$redis->append_command("HINCRBY $ipDstIp|$state|$mtime udp.dstort|$udpDstPort 1");
			$redis->append_command("HINCRBY $ipDstIp|$state|$mtime udp.srcport|$udpSrcPort 1");
		}
		
        } elsif ($ipProto eq "icmp") {
        	$icmp = NetPacket::ICMP->decode($ip->{data});
		$icmpType = $icmp->{type};
		$icmpCode = $icmp->{code};
		$icmpData = $icmp->{data};

		$ref->{$primaryKey}->{icmp}->{type} = $icmpType;
		$ref->{$primaryKey}->{icmp}->{code} = $icmpCode;
		if ($payload == 1) {
			if ($icmp->{data}) {
				$ref->{$primaryKey}->{icmp}->{data} = getClean($icmp->{data});
			}
		}
	} elsif ($ipProto eq "igmp") {
        	$igmp = NetPacket::IGMP->decode($ip->{data});
		$igmpVersion = $igmp->{version};
		$igmpType = $igmp->{type};
		$igmpLen = $igmp->{len};
		$igmpSubtype = $igmp->{subtype};
		$igmpGroupAddr = $igmp->{group_addr};
		$igmpData = $igmp->{data};

		$ref->{$primaryKey}->{igmp}->{version} = $igmpVersion;
		$ref->{$primaryKey}->{igmp}->{type} = $igmpType;
		$ref->{$primaryKey}->{igmp}->{len} = $igmpLen;
		$ref->{$primaryKey}->{igmp}->{subtype} = $igmpSubtype;
		$ref->{$primaryKey}->{igmp}->{group_addr} = $igmpGroupAddr;

		if ($payload == 1) {
			if ($igmp->{data}) {
				$ref->{$primaryKey}->{igmp}->{data} = getClean($igmp->{data});
			}
		}
	}

	# Process Combination Strings
	#my $combo = "$ipProto:$ipLen:$ipTtl:$tcpFlag:$tcpWinsize:$tcpSrcPort:$tcpDstPort:$udpSrcPort:$udpDstPort";

	#unless (exists($ref->{$primaryKey}->{count}->{combo}->{$combo})) {
		#push(@{$ref->{$primaryKey}->{combo}}, $combo);
	#}
	#$ref->{$primaryKey}->{count}->{combo}->{$combo}++;

	if ($useRedis == 1) {
		$redis->append_command("EXPIRE META|$mtime 86400");
		$redis->append_command("EXPIRE $ipDstIp|$state|$mtime 86400");
	}

}


#####################################
# Tag our data in the index 
#####################################
sub addTag {
	my($pkey, $tag) = @_;
	if ($useTags == 1) {
		foreach my $value (@{$ref->{$pkey}->{tags}}) {
			if ($value eq $tag) {
				return;
			}
		}

		push(@{$ref->{$pkey}->{tags}}, "$tag");
		if ($debug == 1) {
			print "$tag tag added to $pkey\n";
		}
	}
	return;
}

#####################################
# Clean up payload data for human consumption 
#####################################
sub getClean {
	my $mess = shift;
	if ($payload == 1) {
		$mess =~ s/\n|\r|\x0D/\./g;
		$mess =~ s/[^[:ascii:]]|[^[:print:]]/\./g;
		$mess = substr($mess, 0, $plBits);
	}

	return($mess);
}

#####################################
# Convert TCP flags to human readable 
#####################################
sub getFlags {
        my $check = shift;
	my @found;
        my %flags = ( 1   => "FIN",
                      2   => "SYN",
                      4   => "RST",
                      8   => "PSH",
                      16  => "ACK",
                      32  => "URG",
                      64  => "ECE",
                      128 => "CWR",
		      256 => "NS",
		      512 => "Unknown[512]"
                    );

        foreach (sort {$b<=>$a} keys %flags) {
                my $num = $_;
                my $next = ($num / 2);
                if ($check <= $num && $check >= $next) {
                        $check -= $next;
			push(@found, $flags{$next});
                }
        }

        return(@found);
}	


