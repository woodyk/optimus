#!/usr/bin/perl
# Optimus packet to profile transform generator 
# author: woodyk@gmail.com
#
# ipv4 traffic distribution generator and indexer
#

use strict;
use bytes;
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
#use NetPacket::IPv6;
#use Netpacket::ICMPv6;
use Search::Elasticsearch;

$ENV{TZ} = 'UTC';
my $hostname = hostname();

my $data = "file.dat";
my $length = 24;
my $verbose;
GetOptions ( "disable_l7" = \$disable_l7,
	     "verbose" = \$verbose,
	     "redis=s" = \$redis,
	     "disable_tag" = \$disable_tag,
	     "elastic=s" = \$elastic,
	   );

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
my $l7Enable	= 1; 			# Enable Layer 7 collection details 0=off 1=on.
my $quiet	= 1; 			# Disable JSON to STDOUT 
my $debug	= 0;			# Enable debugging
my $useRedis	= 0; 			# Redis On or Off
my $useTags	= 1;			# Process tag rules
my $ipv6	= 0;			# Collect IPv6 details
my $geoip	= 1;			# Enable || Disable Geo IP records

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
my $elastic	= 1;			# use elasticsearch
my $esprefix	= 'profiler_';
my @elNodes	= qw(localhost:9200);	# elasticsearch host, and port

#####################################
# Packet Capture options 
#####################################
my $interface	= 'eth1'; 		# Set the interface to listen to and profile.
my $payload	= 1;			# Collect payload sample on or off.
my $plBits	= 64;			# Number of bits into the payload to gather.
my $plOffset	= 0;			# Offset to collect payload at.
my $netFilter	= 0;			# Berkley packet filters to assign to the collection.
my @targetNet	= qw( 192.168.1.0/24 );	# Subnet to to filter for.
my $sample	= 2000;			# Packet samples to process.
my $maxPerDest	= 2000;			# Max packtes per destination IP to record;
my $offline	= 0;			# Offline mode for pcap file processing
my $recType	= 'all';		# Recording type: all, dist, flow, session.
my $pcapFile	= $ARGV[0];		# File name to be processed
chomp($pcapFile);

if ($netFilter == 1) {
	$cidr = Net::CIDR::Lite->new;
	foreach (@targetNet) {
		$cidr->add($_);
	}
}

if ($geoip == 1) {
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
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{match_mapping_type} = 'string';
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{mapping}->{index} = 'not_analyzed';
		#$map->{mappings}->{'_default_'}->{dynamic_templates}->{mapping}->{type} = 'string';

		$map->{mappings}->{'_default_'}->{properties}->{date}->{type} = 'date';
		$map->{mappings}->{'_default_'}->{properties}->{hostname}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{hostname}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{packets}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tags}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{location}->{type} = 'geo_point';
		$map->{mappings}->{'_default_'}->{properties}->{country_code}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{country_code3}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{country_name}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{region}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{region_name}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{city}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{postal_code}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{latitude}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{longitude}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{time_zone}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{area_code}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{continent_code}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{metro_code}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{ver}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{cksum}->{type} = 'long'; ##
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{foffset}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{tos}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{flags}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{len}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{ttl}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{proto}->{type} = 'string';

		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{data}->{type} = 'string';
                $map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{data}->{index} = 'not_analyzed';

                $map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{data}->{type} = 'string';
                $map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{data}->{index} = 'not_analyzed';

                $map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{data}->{type} = 'string';
                $map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{data}->{index} = 'not_analyzed';

                $map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{data}->{type} = 'string';
                $map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{data}->{index} = 'not_analyzed';

		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{src}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{src}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{src}->{index} = 'not_analyzed';

		$map->{mappings}->{'_default_'}->{properties}->{ip}->{properties}->{dst}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{dst}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{raw}->{properties}->{ip}->{properties}->{dst}->{index} = 'not_analyzed';

		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flags}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{SYN}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{FIN}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{ACK}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{ECE}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{URG}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{PSH}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{CWR}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{flag}->{properties}->{RST}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{dstport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{srcport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{window_size}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{hlen}->{type} = 'long'; ##
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{acknum}->{type} = 'long'; ##
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{reserved}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{cksum}->{type} = 'long'; ##
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{urg}->{type} = 'boolean';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{options}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{tcp}->{properties}->{seq}->{type} = 'long'; ##
		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{srcport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{dstport}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{udp}->{properties}->{len}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{type}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{code}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{icmp}->{properties}->{data}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{version}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{type}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{len}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{subtype}->{type} = 'long';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{group_addr}->{type} = 'ip';
		$map->{mappings}->{'_default_'}->{properties}->{igmp}->{properties}->{data}->{type} = 'string';
		# HTTP specific settings
		$map->{mappings}->{'_default_'}->{properties}->{l7}->{properties}->{proto}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{request}->{properties}->{uri}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{request}->{properties}->{uri}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{host}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{host}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"user-agent"}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"user-agent"}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"referer"}->{type} = 'string';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"referer"}->{index} = 'not_analyzed';
		$map->{mappings}->{'_default_'}->{properties}->{http}->{properties}->{header}->{properties}->{"cookie"}->{type} = 'string';
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
		$json->indent();
		if ($geoip == 1) {
			my $locaddy = $ref->{$key}->{ip}->{src};
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
			print $jsonOut;
		}
	}
	$result = $bulk->flush;
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
	my $filter;
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
	my $ether;

	# IP declarations
	my ($ip, $ipLen, $ipCksum, $ipTtl, $ipFoffset, $ipTos, $ipVer, $ipFlags, $ipProto, $ipSrcIp, $ipDstIp, $ipSrcIpInt, $ipDstIpInt);

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
        $ipProto	= getprotobynumber($ip->{proto});
	$ipLen		= $ip->{len};
	$ipTtl		= $ip->{ttl};
	$ipDstIp	= $ip->{dest_ip};
	$ipSrcIp	= $ip->{src_ip};
	$ipDstIpInt	= ip2num("$ip->{dest_ip}");
	$ipSrcIpInt	= ip2num("$ip->{src_ip}");
	$ipFoffset	= $ip->{foffset};
	$ipFlags	= $ip->{flags};
	$ipTos		= $ip->{tos};
	$ipVer		= $ip->{ver};
	$ipCksum	= $ip->{cksum};
	
	if ($netFilter == 1) {
		if (!$cidr->find($ipDstIp) && !$cidr->find($ipSrcIp) ) {
                        #print "Required $targetNet not found.\n";
                        return;
                }
        }

	if ($ipVer == 6) {
		if ($ipv6 == 0) {
			return;
		}
	}
	# Primary key that determines indexing resolution.
	if ($recType eq 'all') {
		$primaryKey = UUID::Random::generate;
	} elsif ($recType eq 'dist') {
		$primaryKey = $ipDstIp;
	}

	# Only collect N samples perl destination IP;
	$beanCounter->{$ipDstIp}++;
	if ($beanCounter->{$ipDstIp} >= $maxPerDest) {
		return;
	}

	$ref->{$primaryKey}->{ip}->{dst} = $ipDstIp;
	$ref->{$primaryKey}->{raw}->{ip}->{dst} = $ipDstIp;
	$ref->{$primaryKey}->{date} = $packetTime;

	# IPv4 Assignment Tagging
	if ($ipDstIp =~ /255/ || $ipSrcIp =~ /255/) {
		addTag($primaryKey, 'BROADCAST');
	}
	if ($ipDstIp =~ /^22[3-9]|^23[0-9]/ || $ipSrcIp =~ /^22[3-9]|^23[0-9]/ ) { 	#223 - 239 = Multicast
		addTag($primaryKey, 'MULTICAST');
	}

	$ref->{$primaryKey}->{packets}++;

	if ($recType eq 'all') {
		$ref->{$primaryKey}->{ip}->{ver} = $ipVer;
		$ref->{$primaryKey}->{ip}->{foffset} = $ipFoffset;
		$ref->{$primaryKey}->{ip}->{tos} = $ipTos;
		$ref->{$primaryKey}->{ip}->{flags} = $ipFlags;
		$ref->{$primaryKey}->{ip}->{len} = $ipLen;
		$ref->{$primaryKey}->{ip}->{ttl} = $ipTtl;
		$ref->{$primaryKey}->{ip}->{proto} = $ipProto;
		$ref->{$primaryKey}->{ip}->{src} = $ipSrcIp;
		$ref->{$primaryKey}->{raw}->{ip}->{src} = $ipSrcIp;
		$ref->{$primaryKey}->{ip}->{cksum} = $ipCksum;
	} elsif ($recType eq 'dist') {	

		unless (exists($ref->{$primaryKey}->{count}->{ip}->{len}->{$ipLen})) {
			push(@{$ref->{$primaryKey}->{ip}->{len}}, $ipLen);
		}
		$ref->{$primaryKey}->{count}->{ip}->{len}->{$ipLen}++;
	
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{ttl}->{$ipTtl})) {
			push(@{$ref->{$primaryKey}->{ip}->{ttl}}, $ipTtl);
		}
		$ref->{$primaryKey}->{count}->{ip}->{ttl}->{$ipTtl}++;
	
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{proto}->{$ipProto})) {
			push(@{$ref->{$primaryKey}->{ip}->{proto}},$ipProto);
		}
		$ref->{$primaryKey}->{count}->{ip}->{proto}->{$ipProto}++;
	
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{src}->{$ipSrcIpInt})) {
			push(@{$ref->{$primaryKey}->{ip}->{src}}, $ipSrcIp);
		}
		$ref->{$primaryKey}->{count}->{ip}->{src}->{$ipSrcIpInt}++;
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{flags}->{$ipFlags})) {
			push(@{$ref->{$primaryKey}->{ip}->{flags}}, $ipFlags);
		}
		$ref->{$primaryKey}->{count}->{ip}->{flags}->{$ipFlags}++;
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{foffset}->{$ipFoffset})) {
			push(@{$ref->{$primaryKey}->{ip}->{foffset}}, $ipFoffset);
		}
		$ref->{$primaryKey}->{count}->{ip}->{foffset}->{$ipFoffset}++;
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{tos}->{$ipTos})) {
			push(@{$ref->{$primaryKey}->{ip}->{tos}}, $ipTos);
		}
		$ref->{$primaryKey}->{count}->{ip}->{tos}->{$ipTos}++;
		unless (exists($ref->{$primaryKey}->{count}->{ip}->{ver}->{$ipVer})) {
			push(@{$ref->{$primaryKey}->{ip}->{ver}}, $ipVer);
		}
		$ref->{$primaryKey}->{count}->{ip}->{ver}->{$ipVer}++;
	}
	
	if ($useRedis == 1) {
		$redis->append_command("HSET META|$mtime $ipDstIp $state");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime count 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.len|$ipLen 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.ttl|$ipTtl 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.proto|$ipProto 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.src|$ipSrcIp 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.dst|$ipDstIp 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.flags|$ipFlags 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.foffset|$ipFoffset 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.tos|$ipTos 1");
		$redis->append_command("HINCRBY $ipDstIp|$state|$mtime ip.ver|$ipVer 1");
	}


        if ($ipProto eq "tcp") {
        	$tcp = NetPacket::TCP->decode($ip->{data});
		# TCP flag inspection module
        	my @tmp = getFlags($tcp->{flags});
		foreach (@tmp) {
			$ref->{$primaryKey}->{tcp}->{flag}->{$_} = 1;
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

		if ($recType eq 'all') {
			$ref->{$primaryKey}->{tcp}->{reserved} = $tcpReserved;
			$ref->{$primaryKey}->{tcp}->{cksum} = $tcpCksum;
			$ref->{$primaryKey}->{tcp}->{urg} = $tcpUrg;
			#$ref->{$primaryKey}->{tcp}->{options} = $tcpOptions;
			$ref->{$primaryKey}->{tcp}->{acknum} = $tcpAckNum;
			$ref->{$primaryKey}->{tcp}->{flags} = $tcpFlag;
			$ref->{$primaryKey}->{tcp}->{hlen} = $tcpHlen;
			$ref->{$primaryKey}->{tcp}->{dstport} = $tcpDstPort;
			$ref->{$primaryKey}->{tcp}->{srcport} = $tcpSrcPort;
			$ref->{$primaryKey}->{tcp}->{seq} = $tcpSeq;
			$ref->{$primaryKey}->{tcp}->{window_size} = $tcpWinsize;
			if ($payload == 1) {
				$ref->{$primaryKey}->{tcp}->{data} = unpack("H64", $tcp->{data});
			}
		} elsif ($recType eq 'dist') {
			unless (exists($ref->{$primaryKey}->{count}->{tcp}->{reserved}->{$tcpReserved})) {
				push(@{$ref->{$primaryKey}->{tcp}->{reserved}}, $tcpReserved);
			}
			$ref->{$primaryKey}->{count}->{tcp}->{reserved}->{$tcpReserved}++;
	
			#unless (exists($ref->{$primaryKey}->{count}->{tcp}->{cksum}->{$tcpCksum})) {
			#	push(@{$ref->{$primaryKey}->{tcp}->{cksum}}, $tcpCksum);
			#}
			#$ref->{$primaryKey}->{count}->{tcp}->{cksum}->{$tcpCksum}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{tcp}->{urg}->{$tcpUrg})) {
				push(@{$ref->{$primaryKey}->{tcp}->{urg}}, $tcpUrg);
			}
			$ref->{$primaryKey}->{count}->{tcp}->{urg}->{$tcpUrg}++;

			#unless (exists($ref->{$primaryKey}->{count}->{tcp}->{options}->{$tcpOptions})) {
			#	push(@{$ref->{$primaryKey}->{tcp}->{options}}, $tcpOptions);
			#}
			#$ref->{$primaryKey}->{count}->{tcp}->{options}->{$tcpOptions}++;
	
			#unless (exists($ref->{$primaryKey}->{count}->{tcp}->{acknum}->{$tcpAckNum})) {
			#	push(@{$ref->{$primaryKey}->{tcp}->{acknum}}, $tcpAckNum);
			#}
			#$ref->{$primaryKey}->{count}->{tcp}->{acknum}->{$tcpAckNum}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{tcp}->{flags}->{$tcpFlag})) {
				push(@{$ref->{$primaryKey}->{tcp}->{flags}}, $tcpFlag);
			}
			$ref->{$primaryKey}->{count}->{tcp}->{flags}->{$tcpFlag}++;
	
			#unless (exists($ref->{$primaryKey}->{count}->{tcp}->{hlen}->{$tcpHlen})) {
			#	push(@{$ref->{$primaryKey}->{tcp}->{hlen}}, $tcpHlen);
			#}
			#$ref->{$primaryKey}->{count}->{tcp}->{hlen}->{$tcpHlen}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{tcp}->{dstport}->{$tcpDstPort})) {
				push(@{$ref->{$primaryKey}->{tcp}->{dstport}}, $tcpDstPort);
			}
			$ref->{$primaryKey}->{count}->{tcp}->{dstport}->{$tcpDstPort}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{tcp}->{srcport}->{$tcpSrcPort})) {
				push(@{$ref->{$primaryKey}->{tcp}->{srcport}}, $tcpSrcPort);
			}
			$ref->{$primaryKey}->{count}->{tcp}->{srcport}->{$tcpSrcPort}++;
	
			#unless (exists($ref->{$primaryKey}->{count}->{tcp}->{seq}->{$tcpSeq})) {
				#push(@{$ref->{$primaryKey}->{tcp}->{seq}, $tcpSeq);
			#}
			#$ref->{$primaryKey}->{count}->{tcp}->{seq}->{$tcpSeq}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{tcp}->{window_size}->{$tcpWinsize})) {
				push(@{$ref->{$primaryKey}->{tcp}->{window_size}}, $tcpWinsize);
			}
			$ref->{$primaryKey}->{count}->{tcp}->{window_size}->{$tcpWinsize}++;
		}

		if ($useRedis == 1) {
				$redis->append_command("HINCRBY $ipDstIp|$state|$mtime tcp.flag|$tcp->{flags} 1");
				$redis->append_command("HINCRBY $ipDstIp|$state|$mtime tcp.dstport|$tcpDstPort 1");
				$redis->append_command("HINCRBY $ipDstIp|$state|$mtime tcp.srcport|$tcpSrcPort 1");
				#$redis->append_command("HINCRBY $ipDstIp|$state|$mtime tcpSeqNum|$tcpSeq 1");
				$redis->append_command("HINCRBY $ipDstIp|$state|$mtime tcp.window_size|$tcpWinsize 1");
		}
		
		# HTTP inspection module
		if ($l7Enable == 1) {
			# HTTP requests
			my $tcpPayload = unpack("H*", $tcp->{data});
			#my $payload = unpack("B*", $tcp->{data});
			# use substr for offset and string manipulation
	
			if ($tcp->{data} =~ /^GET |^POST |^HEAD |^PUT |^DELETE |^TRACE |^CONNECT /i) {
				my @lines = split("\n", $tcp->{data});
				#print "$lines[0]\n";
				my $methUri = shift(@lines);
				my @methodData = split(" ", $methUri);

				if ($recType eq 'all') {
					$ref->{$primaryKey}->{l7}->{proto} = 'http';
					$ref->{$primaryKey}->{http}->{request}->{method} = $methodData[0];
					$ref->{$primaryKey}->{http}->{request}->{uri} = $methodData[1];
					$ref->{$primaryKey}->{http}->{request}->{version} = $methodData[2];
					if ($debug == 1) {
						print "layer 7: l7.proto:http http.request method:$methodData[0] uri:$methodData[1] version:$methodData[2]\n";
					}
				} elsif ($recType eq 'dist') {
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
				}
				#$ref->{$primaryKey}->{count}->{http}->{request}->{uri}->{$methodData[1]}++;
				if ($useRedis == 1) {
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

					if ($recType eq "all") {
						$ref->{$primaryKey}->{http}->{header}->{$header} = $headerContent;
					} elsif ($recType eq "dist") {
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
						#print "$header $headerContent\n";
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
			}
		}
                #print $ipSrcIp, " ", $ipDstIp, " ", $ipProto, " ", $tmp, " ", $tcp->{data}, "\n"
        } elsif ($ipProto eq "udp") {
        	$udp = NetPacket::UDP->decode($ip->{data});
		$udpDstPort = $udp->{dest_port};
		$udpSrcPort = $udp->{src_port};
		$udpLen	    = $udp->{len};

		if ($recType eq 'all') {
			$ref->{$primaryKey}->{udp}->{dstport} = $udpDstPort;
			$ref->{$primaryKey}->{udp}->{srcport} = $udpSrcPort;
			$ref->{$primaryKey}->{udp}->{len} = $udpLen;
			if ($payload == 1) {
				$ref->{$primaryKey}->{udp}->{data} = unpack("H64", $udp->{data});
			}
		} elsif ($recType eq 'dist') {
			unless (exists($ref->{$primaryKey}->{count}->{udp}->{dstport}->{$udpDstPort})) {
				push(@{$ref->{$primaryKey}->{udp}->{dstport}}, $udpDstPort);
			}
			$ref->{$primaryKey}->{count}->{udp}->{dstport}->{$udpDstPort}++;
	
			unless (exists($ref->{$primaryKey}->{count}->{udp}->{srcport}->{$udpSrcPort})) {
				push(@{$ref->{$primaryKey}->{udp}->{srcport}}, $udpSrcPort);
			}
			$ref->{$primaryKey}->{count}->{udp}->{srcport}->{$udpSrcPort}++;
	
			#unless (exists($ref->{$primaryKey}->{count}->{udp}->{len}->{$udpLen})) {
			#	push(@{$ref->{$primaryKey}->{udp}->{len}}, $udpLen);
			#}
			#$ref->{$primaryKey}->{count}->{udp}->{len}->{$udpLen}++;
	
		}
	
	
		if ($useRedis == 1) {
			$redis->append_command("HINCRBY $ipDstIp|$state|$mtime udp.dstort|$udpDstPort 1");
			$redis->append_command("HINCRBY $ipDstIp|$state|$mtime udp.srcport|$udpSrcPort 1");
		}
		
		#my $offset = substr($udp->{data}, -10);
		#print "$offset ***\n";
        } elsif ($ipProto eq "icmp") {
        	$icmp = NetPacket::ICMP->decode($ip->{data});
		$icmpType = $icmp->{type};
		$icmpCode = $icmp->{code};
		$icmpData = $icmp->{data};

		if ($recType eq 'all') {
			$ref->{$primaryKey}->{icmp}->{type} = $icmpType;
			$ref->{$primaryKey}->{icmp}->{code} = $icmpCode;
			if ($payload == 1) {
				$ref->{$primaryKey}->{icmp}->{data} = unpack("H64", $icmp->{data});
			}
		} elsif ($recType eq 'dist') {

		}
	} elsif ($ipProto eq "igmp") {
        	$igmp = NetPacket::IGMP->decode($ip->{data});
		$igmpVersion = $igmp->{version};
		$igmpType = $igmp->{type};
		$igmpLen = $igmp->{len};
		$igmpSubtype = $igmp->{subtype};
		$igmpGroupAddr = $igmp->{group_addr};
		$igmpData = $igmp->{data};

		if ($recType eq 'all') {
			$ref->{$primaryKey}->{igmp}->{version} = $igmpVersion;
			$ref->{$primaryKey}->{igmp}->{type} = $igmpType;
			$ref->{$primaryKey}->{igmp}->{len} = $igmpLen;
			$ref->{$primaryKey}->{igmp}->{subtype} = $igmpSubtype;
			$ref->{$primaryKey}->{igmp}->{group_addr} = $igmpGroupAddr;
			if ($payload == 1) {
				$ref->{$primaryKey}->{igmp}->{data} = unpack("H64", $igmp->{data});
			}
		} elsif ($recType eq 'dist') {

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
