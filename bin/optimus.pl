#!/usr/bin/env perl
#
# File: optimus.pl
# Author: Wadih Khairallah
# Description: 
# Created: 2025-06-03 01:59:21

use strict;
use warnings;
use bytes;
use JSON;
use POSIX;
use Socket;
use Getopt::Long;
use Net::Pcap;
use File::Spec;
use UUID::Tiny ':std';
use Data::Dumper;
use Sys::Hostname;
use Sys::Syslog;
use Net::IPAddress;
use NetPacket::IP qw(:strip);
use NetPacket::ARP qw(:strip);
use NetPacket::TCP qw(:strip);
use NetPacket::UDP qw(:strip);
use NetPacket::ICMP qw(:strip);
use NetPacket::IGMP qw(:strip);
use NetPacket::Ethernet qw(:strip);
use NetPacket::IPv6 qw(:strip);
use NetPacket::ICMPv6 qw(:strip);
use Search::Elasticsearch;
use MaxMind::DB::Reader;
use IPC::Open3;

# Signal handlers
$SIG{INT} = sub { die "Caught a sigint $!" };
$SIG{TERM} = sub { die "Caught a sigterm $!" };
$ENV{TZ} = 'UTC';

# Set running directory
my $absPath = File::Spec->rel2abs($0);
$absPath =~ s/$0$//;
chdir($absPath);

# Configurable options.
my $ouiFile = '/tmp/wireshark_oui.txt';		# Location to store OUI data file.
my $geoIpDb = '../lib/GeoLite2-City.mmdb';	# Path to geoip database.
my $dataSource = "live";			# Default datasource label for JSON documents.
my $esPrefix = "packets_";			# Elasticsearch index prefix.
my $ouiUrl = 'https://gitlab.com/wireshark/wireshark/-/raw/master/manuf';	# URL to OUI data file.
my $oui_sched = 86400;				# Age of OUI file before it is refreshed. 

my $hostname = hostname();
my $ref; 				    # Hash reference for all the collected samples.
my $interface;				# Network interface to listen to.
my $beanCounter;			# Packet counter.
my $debug;			    	# Debug default off.
my $pcapFile;				# Variable to pcap file path.
my $displayJson;			# JSON output default off.
my $logging;				# Logging default off. 
my $esNode;	    			# Elasticsearch node used for injection.
my $geoIp;			    	# GeoIP lookup default off.
my $nameLookup;				# Reverse DNS lookup default off.
my $pktCounter;				# Packet counter.
my $sample;			    	# Variable for number of packets to collect.
my $l7Enable;				# Layer 7 data collection default off.
my $payloadBytes;			# Number of bytes to collect from the payload.
my $dummy;
my $message;

if (!@ARGV) {
    help();
}

# Get command line options.
GetOptions(
	'bytes=i'	    => \$payloadBytes,
	'count=i'   	=> \$sample,
	'debug'		    => sub { $debug = 1; },
	'dummy'	    	=> sub { $dummy = 1; },
    'interface=s'   => \$interface,
    'pcap=s'        => \$pcapFile,
    'json'  		=> sub { $displayJson = 1; },
	'help'		    => \&help,
	'server=s'  	=> \$esNode,
	'l7'		    => sub { $l7Enable = 1; },
	'log'		    => sub { $logging = 1},
	'revlookup' 	=> sub { $nameLookup = 1; },
	'tag=s'		    => \$dataSource,
	'geoip'		    => sub { $geoIp = 1; }
);
logIt("started.");

# Dummy mode for testing and docker api only.
if (defined($dummy)) {
	while (1) {
		print "Running in dummy mode.\n";
		sleep 120;
	}
}

# Sanity checks for elasticsearch switches.
if (defined($esNode)) {
	if ($esNode !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}$/) {
		my ($host, $port) = split(/:/, $esNode);

		my $ip = inet_ntoa(inet_aton($host)) || die "Invalid hostname $host.";

		$esNode = "$ip:$port";
	}

	if (defined($geoIp)) {
		$message = "Disabling GeoIp.  Elasticsearch pipelines should be used for GeoIP recording.\n";
		print "$message";
		logIt($message);
		undef($geoIp);
	}
}

# Sanity checks for interface switches.
if (defined($interface) && !defined($sample)) {
	$message = "No packet count has been defined. Use -c.\n";
	logIt($message);
	die $message;
}

#####################################
# Make sure we have the IEEE Vendor data file
# Checking if we should update.
#####################################
my %oui;
my $oui_access;
my $oui_age = 0;
my $epoch = time();

if (-e $ouiFile) {
	$oui_access 	  = (stat $ouiFile)[9];
	$oui_age    	  = ($epoch - $oui_access);
}

if ($oui_age >= $oui_sched || !-f $ouiFile) {
	my $chld_in;
	my $pid = open3($chld_in, '>&STDOUT', '>&STDERR', "wget -O $ouiFile $ouiUrl") or die "Unable to execute command: $!\n";
	waitpid($pid, 0);
}

open(my $OUI, '<', "$ouiFile") or die $!;
while (my $line = <$OUI>) {
	if ($line !~ /^\#/) {
		my($address, $vendor, $vendor_long) = split(/\t+/, $line);

		if ($vendor) {
			chomp($vendor);
		}

		if ($vendor_long) {
			chomp($vendor_long);
		} else {
			$vendor_long = $vendor;
		}

		$address =~ s/://g;
		$oui{$address} = $vendor_long;
	}
}
close($OUI);
$oui{FFFFFF} = "broadcast";

#####################################
# Check that a file has been given if
# running in pcap read mode
#####################################

if (defined($pcapFile)) {
	$interface = "pcap";
	if (!-e $pcapFile) {
		$message = "Unable to find file $pcapFile for processing.\n";
		logIt($message);
		die $message;
	}

	if (!defined($sample)) {
		$sample = -1;
	}
}

#####################################
# Begin collection of samples and
# output the parsed results.
#####################################
capture($interface, $sample);
output();
exit;

#####################################
# Process our output 
#####################################
sub output {
	debugIt("Starting output processing.\n");

	my @jsonArray;

	my $startTime = time();

	my $indexstamp = strftime("%Y.%m.%d.%H", localtime());
	my $indexname = $esPrefix.$indexstamp;

	my $e;
	my $bulk;
	if (defined($esNode)) {
		$e = Search::Elasticsearch->new( nodes => $esNode ); 

		unless ($e->indices->exists(index => "$indexname")) {
			my $result = $e->indices->create(
				index => $indexname
			);
		}
		$bulk = $e->bulk_helper( max_count => 100,
					 max_time  => 300 );
	}

	my $gi;
	if (defined($geoIp)) {
		$gi = MaxMind::DB::Reader->new(file => $geoIpDb);
	}

	$pktCounter = 0;
	foreach my $key (keys(%{$ref})) {

		my $hashSize = length($ref->{$key});
		if ($hashSize <= 1) {
			next;
		}
		$pktCounter++;	
		
		$ref->{$key}->{hostname} = $hostname;
		$ref->{$key}->{interface} = $interface;
		$ref->{$key}->{datasource} = $dataSource;

		if ($ref->{$key}->{protos}->{l2} eq "ip_route") {
			if (defined($geoIp)) {
				my $record;
	
				if ($ref->{$key}->{ip}->{src}) {
					if ($record = $gi->record_for_address($ref->{$key}->{ip}->{src})) {
						$ref->{$key}->{geoip}->{src}->{country_code} = $record->{country}->{iso_code};
						$ref->{$key}->{geoip}->{src}->{country_name} = $record->{country}->{names}->{en};
						$ref->{$key}->{geoip}->{src}->{city} = $record->{city}->{names}->{en};
						$ref->{$key}->{geoip}->{src}->{postal_code} = $record->{postal}->{code};
						$ref->{$key}->{geoip}->{src}->{location} = $record->{location}->{latitude}.",".$record->{location}->{longitude};
						$ref->{$key}->{geoip}->{src}->{time_zone} = $record->{location}->{time_zone};
						$ref->{$key}->{geoip}->{src}->{continent_name} = $record->{continent}->{names}->{en};
						$ref->{$key}->{geoip}->{src}->{subdivision_code} = $record->{subdivisions}[0]->{iso_code};
						$ref->{$key}->{geoip}->{src}->{subdivision_name} = $record->{subdivisions}[0]->{names}->{en};
					}
				}

				if ($ref->{$key}->{ip}->{dst}) {
					if ($record = $gi->record_for_address($ref->{$key}->{ip}->{dst})) {
						$ref->{$key}->{geoip}->{dst}->{country_code} = $record->{country}->{iso_code};
						$ref->{$key}->{geoip}->{dst}->{country_name} = $record->{country}->{names}->{en};
						$ref->{$key}->{geoip}->{dst}->{city} = $record->{city}->{names}->{en};
						$ref->{$key}->{geoip}->{dst}->{postal_code} = $record->{postal}->{code};
						$ref->{$key}->{geoip}->{dst}->{location} = $record->{location}->{latitude}.",".$record->{location}->{longitude};
						$ref->{$key}->{geoip}->{dst}->{time_zone} = $record->{location}->{time_zone};
						$ref->{$key}->{geoip}->{dst}->{continent_name} = $record->{continent}->{names}->{en};
						$ref->{$key}->{geoip}->{dst}->{subdivision_code} = $record->{subdivisions}[0]->{iso_code};
						$ref->{$key}->{geoip}->{dst}->{subdivision_name} = $record->{subdivisions}[0]->{names}->{en};
					}
				}
			}

			if (defined($nameLookup)) {	
				$ref->{$key}->{dns}->{src} = revDns($ref->{$key}->{ip}->{src});
				$ref->{$key}->{dns}->{dst} = revDns($ref->{$key}->{ip}->{dst});
			}

		}
			
		if (defined($esNode)) {
			$bulk->create({ index 	=> $indexname,
					id	=> $key,
					source	=> $ref->{$key} });
		}

		if (defined($displayJson)) {
			$ref->{$key}->{id} = $key;
			push(@jsonArray, $ref->{$key});
		}

	}

	if (defined($displayJson)) {
		my $json = JSON->new();	
		$json->indent();
		$json->canonical();
		my $jsonOut = $json->utf8->encode(\@jsonArray);
		print "$jsonOut\n";
	}

	if (defined($esNode)) {
		my $result = $bulk->flush;
		$message = "Wrote $pktCounter packets to elasticsearch.\n";
		debugIt($message);
		logIt($message);
	}

	my $stopTime = time();
	my $runTime = ($stopTime - $startTime);

	debugIt("Processed $pktCounter total packets.\n");
	debugIt("Finished output processing in $runTime seconds.\n");

	return;
}

#####################################
# Capture network traffic 
#####################################
sub capture {
	debugIt("Starting packet capture.\n");

	my $startTime = time();

	my ($dev, $packets) = @_;
        my $err;
	my $pcap;
	my $filter = "";
	my $filter_compiled;

	# Prepare interface for collection.
	if (defined($pcapFile)) {
        	$pcap = Net::Pcap::open_offline($pcapFile, \$err);
	} else {
        	$pcap = Net::Pcap::open_live($dev, 2048, 1, 0, \$err);
	}
	#$SIG{ALRM} = sub { Net::Pcap::close($pcap); sleep 1; display(); };

        if (!defined($pcap)) {
                $message = "Unable to capture traffic.\n$err\n";
		logIt($message);
		die $message;
        }

        Net::Pcap::compile($pcap, \$filter_compiled, $filter, 0, 0) && warn "Unable to create filter.\n";;

        Net::Pcap::setfilter($pcap, $filter_compiled) && warn "Unable to set filter.\n";
        #alarm $packets;

        Net::Pcap::loop($pcap, $packets, \&packetParse, '');
	Net::Pcap::close($pcap);

	my $stopTime = time();
	my $runTime = ($stopTime - $startTime);

	debugIt("Finished packet capture in $runTime seconds.\n");
	return;
}

#####################################
# Network packet parser
#####################################
sub packetParse {
        my ($user_data, $header, $packet) = @_;
	
	my $payloadData;

	# Assign a unique UUID for this packet.
	my $primaryKey = uuid_to_string(create_uuid(UUID_RANDOM));

        my $ipAddressForBeanCounter = "unknown";
	my $ipProto = "unknown";
	$ref->{$primaryKey}->{protos}->{l2}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l3}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l4}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l5}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l6}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l7}   = "unknown";

	# Set the time to the current minute rounded down to the first second.
	my $packetTime = strftime("%Y-%m-%dT%H:%M:%S", localtime($header->{tv_sec}));
	$ref->{$primaryKey}->{date} = $packetTime;

	# Layer 2 data
        my $ether = NetPacket::Ethernet::strip($packet);
	my $eth_obj = NetPacket::Ethernet->decode($packet);

	if ($eth_obj->{type} == "2054") { #ARP
		my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);

		$ref->{$primaryKey}->{protos}->{l2}   = "arp";
		$ref->{$primaryKey}->{arp}->{htype}  = $arp_obj->{htype};
		$ref->{$primaryKey}->{arp}->{proto}  = $arp_obj->{proto};
		$ref->{$primaryKey}->{arp}->{hlen}   = $arp_obj->{hlen};
		$ref->{$primaryKey}->{arp}->{opcode} = $arp_obj->{opcode};
		$ref->{$primaryKey}->{arp}->{sha}    = uc($arp_obj->{sha});
		$ref->{$primaryKey}->{arp}->{spa}    = uc($arp_obj->{spa});
		$ref->{$primaryKey}->{arp}->{tha}    = uc($arp_obj->{tha});
		$ref->{$primaryKey}->{arp}->{tpa}    = uc($arp_obj->{tpa});

	} elsif ($eth_obj->{type} == "2048") { # IP_ROUTE
		$ref->{$primaryKey}->{protos}->{l2} = "ip_route";

	}

	$ref->{$primaryKey}->{mac}->{src}  = uc($eth_obj->{src_mac});
	$ref->{$primaryKey}->{mac}->{dst}  = uc($eth_obj->{dest_mac});

	# Populate OUI data for mac addresses.
	my $srcV = substr($ref->{$primaryKey}->{mac}->{src}, 0, 6);
	my $dstV = substr($ref->{$primaryKey}->{mac}->{dst}, 0, 6);
	if (exists($oui{$srcV})) {
		$srcV = $oui{$srcV};
	} else {
		$srcV = "unknown";
	}

	if (exists($oui{$dstV})) {
		$dstV = $oui{$dstV};
	} else {
		$dstV = "unknown";
	}
	$ref->{$primaryKey}->{mac}->{src_vendor} = $srcV;
	$ref->{$primaryKey}->{mac}->{dst_vendor} = $dstV;

	# Layer 3 
	my $ip = NetPacket::IP->decode($ether);

	# IPv4
	if ($ip->{ver} == 4) {
		$ref->{$primaryKey}->{protos}->{l3} = "ip";

		if (defined($ip->{proto})) {
			$ipProto = getprotobynumber($ip->{proto});
			$ref->{$primaryKey}->{ip}->{proto} = $ipProto;
		}

		$ref->{$primaryKey}->{ip}->{dst} 	= $ip->{dest_ip};
		$ref->{$primaryKey}->{ip}->{src} 	= $ip->{src_ip};
		$ref->{$primaryKey}->{ip}->{foffset} 	= $ip->{foffset};
		$ref->{$primaryKey}->{ip}->{tos} 	= $ip->{tos};
		$ref->{$primaryKey}->{ip}->{flags} 	= $ip->{flags};
		$ref->{$primaryKey}->{ip}->{len} 	= $ip->{len};
		$ref->{$primaryKey}->{ip}->{hlen} 	= $ip->{hlen};
		#$ref->{$primaryKey}->{ip}->{options} 	= $ip->{options};
		$ref->{$primaryKey}->{ip}->{ttl} 	= $ip->{ttl};
		$ref->{$primaryKey}->{ip}->{cksum} 	= $ip->{cksum};
		$ref->{$primaryKey}->{ip}->{ver} 	= $ip->{ver};
		$ipAddressForBeanCounter = $ref->{$primaryKey}->{ip}->{dst};

		# IPv4 type       
                if ($ref->{$primaryKey}->{ip}->{dst} =~ /^255\.255\.255\.255/) {
			$ref->{$primaryKey}->{ip}->{type} = 'broadcast';
                } elsif ($ref->{$primaryKey}->{ip}->{dst} =~ /^22[4-9]\.|^23[0-9]\./ ) {
			$ref->{$primaryKey}->{ip}->{type} = 'multicast';
                } else {
			$ref->{$primaryKey}->{ip}->{type} = 'unicast';
		}
	}

	# IPv6
	if ($ip->{ver} == 6) {
		$ref->{$primaryKey}->{protos}->{l3} = "ipv6";

  		my $ip6 = NetPacket::IPv6->decode($ether);

		if (defined($ip6->{proto})) {
        		$ipProto = getprotobynumber($ip6->{proto});
			$ref->{$primaryKey}->{ip}->{proto} = $ipProto;
		}
		$ref->{$primaryKey}->{ip}->{src}       	= $ip6->{src_ip};
                $ref->{$primaryKey}->{ip}->{dst}       	= $ip6->{dest_ip};
                $ref->{$primaryKey}->{ip}->{class}     	= $ip6->{traffic_class};
                $ref->{$primaryKey}->{ip}->{flow}      	= $ip6->{flow_label};
                $ref->{$primaryKey}->{ip}->{hop_limit} 	= $ip6->{hop_limit};
                $ref->{$primaryKey}->{ip}->{ver}	= $ip6->{ver};
                $ref->{$primaryKey}->{ip}->{len} 	= $ip6->{len};
                $ref->{$primaryKey}->{ip}->{type}	= $ip6->{type};
		
		$ipAddressForBeanCounter = $ref->{$primaryKey}->{ip}->{dst};

		# IPv6 type
                if ($ref->{$primaryKey}->{ip}->{dst} =~ /^ff[0-9a-f][0-9a-f]:/ ) {
			$ref->{$primaryKey}->{ip}->{type} = 'multicast';
                }
	}
	
	# Collect packet count for each IP seen.
	$beanCounter->{$ipAddressForBeanCounter}++;

	# TCP
        if ($ipProto eq "tcp") {
        	my $tcp = NetPacket::TCP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l4} = "tcp";
		$payloadData = $tcp->{data};

		# TCP flag inspectione
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
		my $tcpFlag;
		foreach (@tmp) {
			$ref->{$primaryKey}->{tcp}->{flag}->{$_} = "true";
			$tcpFlag .= "$_:";	
		}
		$tcpFlag =~ s/:$//;
		
		$ref->{$primaryKey}->{tcp}->{srcport}		= $tcp->{src_port};
		$ref->{$primaryKey}->{tcp}->{dstport}		= $tcp->{dest_port};
		$ref->{$primaryKey}->{tcp}->{seqnum}		= $tcp->{seqnum};
		$ref->{$primaryKey}->{tcp}->{acknum}		= $tcp->{acknum};
		$ref->{$primaryKey}->{tcp}->{hlen}		= $tcp->{hlen};
		$ref->{$primaryKey}->{tcp}->{reserved}		= $tcp->{reserved};
		$ref->{$primaryKey}->{tcp}->{flags}		= $tcpFlag;
		$ref->{$primaryKey}->{tcp}->{winsize}		= $tcp->{winsize};
		$ref->{$primaryKey}->{tcp}->{cksum}		= $tcp->{cksum};
		$ref->{$primaryKey}->{tcp}->{urg}		= $tcp->{urg};
		#$ref->{$primaryKey}->{tcp}->{options}		= $tcp->{options};

		if (defined($payloadBytes)) {
			if ($payloadData) {
				$ref->{$primaryKey}->{tcp}->{data} = toAscii($payloadData);
				# Add hex payload for pattern matching.
				#my $hex = uc(unpack("H*", $tcp->{data}));
			}
		}

		# Layer 7 
		if (defined($l7Enable)) {
			# SSH Straffic
                        if ($ref->{$primaryKey}->{tcp}->{dstport} == 22 || $ref->{$primaryKey}->{tcp}->{srcport} == 22 || $payloadData =~ /^ssh-[12]\.[0-9]/i) {
				$ref->{$primaryKey}->{protos}->{l7} = "ssh";
                        }

		}

	# UDP
        } elsif ($ipProto eq "udp") {
        	my $udp = NetPacket::UDP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l4} = "udp";
		$payloadData = $udp->{data};

		$ref->{$primaryKey}->{udp}->{dstport}	= $udp->{dest_port};
		$ref->{$primaryKey}->{udp}->{srcport}	= $udp->{src_port};
		$ref->{$primaryKey}->{udp}->{len}	= $udp->{len};

		if (defined($payloadBytes)) {
			if ($payloadData) {
				$ref->{$primaryKey}->{udp}->{data} = toAscii($payloadData);
			}
		}

		# Layer 7
		if (defined($l7Enable)) {
			# DNS Traffic
			if ($ref->{$primaryKey}->{udp}->{dstport} == 53 || $ref->{$primaryKey}->{udp}->{srcport} == 53) {
				$ref->{$primaryKey}->{protos}->{l7} = "dns";
                	}

			# mDNS Traffic
			if ($ref->{$primaryKey}->{udp}->{dstport} == 5353 || $ref->{$primaryKey}->{udp}->{srcport} == 5353) {
				$ref->{$primaryKey}->{protos}->{l7} = "mdns";
                	}

			# NTP Traffic
			if (($ref->{$primaryKey}->{udp}->{dstport} == 123 || $ref->{$primaryKey}->{udp}->{srcport} == 123) && $payloadData =~ /^([\x13\x1b\x23\xd3\xdb\xe3]|[\x14\x1c$].......?.?.?.?.?.?.?.?.?[\xc6-\xff])/) {
				$ref->{$primaryKey}->{protos}->{l7} = "ntp";
			}
		}

	# ICMP
        } elsif ($ipProto eq "icmp") {
        	my $icmp = NetPacket::ICMP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l3} = "icmp";
		$payloadData = $icmp->{data};

		$ref->{$primaryKey}->{icmp}->{type} = $icmp->{type};
		$ref->{$primaryKey}->{icmp}->{code} = $icmp->{code};

		if (defined($payloadBytes)) {
			if ($payloadData) {
				$ref->{$primaryKey}->{icmp}->{data} = toAscii($payloadData);
			}
		}

	# ICMPv6
	} elsif ($ipProto eq "ipv6-icmp") {
		my $icmpV6 = NetPacket::ICMPv6->decode(ipv6_strip(eth_strip($packet)));

		$ref->{$primaryKey}->{protos}->{l3} = "ipv6-icmp";
		$payloadData = $icmpV6->{data};

		$ref->{$primaryKey}->{ipv6_icmp}->{type} = $icmpV6->{type};
		$ref->{$primaryKey}->{ipv6_icmp}->{code} = $icmpV6->{code};
		$ref->{$primaryKey}->{ipv6_icmp}->{cksum} = $icmpV6->{cksum};

		if (defined($payloadBytes)) {
			if ($payloadData) {
				$ref->{$primaryKey}->{ipv6_icmp}->{data} = toAscii($payloadData);
			}
		}

	# IGMP
	} elsif ($ipProto eq "igmp") {
        	my $igmp = NetPacket::IGMP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l3} = "igmp";
		$payloadData = $igmp->{data};

		$ref->{$primaryKey}->{igmp}->{version}		= $igmp->{version};
		$ref->{$primaryKey}->{igmp}->{type}		= $igmp->{type};
		$ref->{$primaryKey}->{igmp}->{len}		= $igmp->{len};
		$ref->{$primaryKey}->{igmp}->{subtype}		= $igmp->{subtype};
		$ref->{$primaryKey}->{igmp}->{group_addr}	= $igmp->{group_addr};
		$ref->{$primaryKey}->{igmp}->{cksum}		= $igmp->{cksum};

		if (defined($payloadBytes)) {
			if ($payloadData) {
				$ref->{$primaryKey}->{igmp}->{data} = toAscii($payloadData);
			}
		}
	}

	# Layer 7
	if (defined($l7Enable)) {
		if ($ipProto =~ /^tcp$|^udp$/ && defined($payloadData)) {
			# SSL Traffic
                        if ($payloadData =~ /^(.?.?\x16\x03.*\x16\x03|.?.?\x01\x03\x01?.*\x0b)|(3t.?.?.?.?.?.?.?.?.?.?h2.?http\/1\.1.?.?)/) {
				$ref->{$primaryKey}->{protos}->{l7} = "ssl";
                        }

			# HTTP Headers Pattern 
			my $httpHeaders = qr/^Accept|^Access-|^Age|^Allow|^Alt-Svc|^Authorization|^Cache-Control|^Clear-Site-Data|^Connection|^Content-|^Cookie|^Cross-|^Date|^Device-Memory|^Digest|^DNT|^Downlink|^DPR|^Early-Data|^ECT|^ETag|^Expect|^Expires|^Feature-Policy|^Forwarded|^From|^Host|^If-|^Keep-Alive|^Large-Allocation|^Last-Modified|^Link|^Location|^Max-Forwards|^NEL|^Origin|^Pragma|^Proxy-|^Range|^Referer|^Referrer-Policy|^Retry-After|^RTT|^Save-Data|^Sec-|^Server|^Service-Worker-Navigation-Preload|^Set-Cookie|^SourceMap|^Strict-Transport-Security|^TE|^Timing-Allow-Origin|^Tk|^Trailer|^Transfer-Encoding|^Upgrade|^User-Agent|^Vary|^Via|^Viewport-Width|^Want-Digest|^Warning|^Width|^WWW-Authenticate|^X-/; 	

			# HTTP Request	
			if ($payloadData =~ /^GET|^POST|^HEAD|^PUT|^DELETE|^TRACE|^CONNECT|^OPTIONS|^PATCH/i) {
				my @lines = split("\n", $payloadData);
				my $methUri = shift(@lines);
				my @methodData = split(" ", $methUri);

				$ref->{$primaryKey}->{protos}->{l7} = 'http';
				$ref->{$primaryKey}->{http}->{request}->{method} = $methodData[0];
				$ref->{$primaryKey}->{http}->{request}->{uri} = $methodData[1];
				$ref->{$primaryKey}->{http}->{request}->{version} = $methodData[2];

				foreach (@lines) {

					if ($_ !~ /:/) {
						next;
					}

					my ($header,$headerContent) = split(/: /, $_);
					if ($header !~ /$httpHeaders/i) {
						next;
					}
				
					if ($header =~ /\r/) {
						next;
					}

					$header = lc($header);
					$headerContent =~ s/^ //;
					$headerContent =~ s/\s+\r$|\r$//;

					$ref->{$primaryKey}->{http}->{request}->{header}->{$header} = $headerContent;
				}
			}
			# HTTP Response
			if ($payloadData =~ /^HTTP\/\d/i) {
                                my @lines = split("\r\n", $payloadData);
                                my $responseHeader = shift(@lines);
                                my ($resVersion, $resCode, $resStatus) = split(" ", $responseHeader);

				$ref->{$primaryKey}->{protos}->{l7} = 'http';
				$ref->{$primaryKey}->{http}->{response}->{version} = $resVersion;
				$ref->{$primaryKey}->{http}->{response}->{code} = $resCode;
				$ref->{$primaryKey}->{http}->{response}->{status} = $resStatus;

				foreach (@lines) {

					if ($_ !~ /:/) {
						next;
					}

					my ($header,$headerContent) = split(/: /, $_);
					if ($header !~ /$httpHeaders/i) {
						next;
					}

					$header = lc($header);
					$headerContent =~ s/^ //;
					$headerContent =~ s/\s+\r$|\r$//;

					$ref->{$primaryKey}->{http}->{response}->{header}->{$header} = $headerContent;
				}
			}
		}
	}

	return;	
}

#####################################
# Tag our data in the index 
#####################################
sub addTag {
	my($pkey, $tag) = @_;
	foreach my $value (@{$ref->{$pkey}->{tags}}) {
		if ($value eq $tag) {
			return;
		}
	}

	push(@{$ref->{$pkey}->{tags}}, "$tag");
	return;
}

#####################################
# Convert payload data to ASCII
# printable 
#####################################
sub toAscii {
	my $pktData = shift;
	if (defined($payloadBytes)) {
		$pktData =~ s/\n|\r|\x0D/\./g;
		$pktData =~ s/[^[:ascii:]]|[^[:print:]]/\./g;
		#$pktData =~ s/[^ -~]/\./g;
		$pktData = substr($pktData, 0, $payloadBytes);
	} else {
		$pktData = "";
	}

	return($pktData);
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
		      512 => "unknown"
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

#####################################
# Log messages to syslog local0 
#####################################
sub logIt {
	$message = shift;
	if (defined($logging)) {
		openlog("$0", "ndelay,pid", "local0");
		syslog("info|local0", $message);
		closelog();
	}
	return;
}

#####################################
# Print message to stdout for debug 
#####################################
sub debugIt {
	$message = shift;
	if (defined($debug)) {
		print "$message";
	}
	return;
}

#####################################
# Reverse DNS lookup on ip addresses 
#####################################
sub revDns {
	my $ip = shift;
	if (defined($ip)) {
		my $ipaddr = inet_aton($ip);
		my $revHost = gethostbyaddr($ipaddr, AF_INET);
		if (defined($revHost)) {
			return($revHost);
		} else {
			return("unknown");
		}
	}
}

#####################################
# help output 
#####################################
sub help {
	my $helpOutput = <<menuEnd;
$0 [options]
	-c          Number of packets to process.
	--bytes     Number of bytes to collect from the payload. Default: none
	--debug     Output debug information to STDOUT.
	--dummy     Run in dummy mode. No actions taken just run for 120 seconds.
	--geoip     Enable geoip collection.
	--help      This help output.
	-i          Interface to listen to.
	--json      Output JSON array to STDOUT.
	-l          Enable syslog logging.
	--l7        Enable layer 7 data collection.
	-p          Pcap file for reading.
	-r          Enable reverse DNS lookup. (much slower)
	--server    Elastic search server with port. eg: 192.168.1.10:9200
	-t          Label name for your datasource.

Examples:
	Listen to eth0 for 10 packets, output JSON, enable L7, process GeoIP.

	$0 -i eth0 -c 10 --json --l7 --geoip --bytes 1024

	Read from pcap file and output JSON, enable L7, process GeoIP.

	$0 -p /path/to/pcap --jason --geoip --l7

	Listen to eth0 for 1000 packets ,inject to elasticsearch, capture
	1024 bytes of payload, process layer7 data.

	$0 -i eth0 -c 1000 --server 192.168.0.10:9200 --bytes 1024 --l7

menuEnd

	print "$helpOutput";

	exit;
}
