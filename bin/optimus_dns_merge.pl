#!/usr/bin/perl
# Optimus packet to profile transform generator 
# author: woodyk@gmail.com
#
# ipv4 traffic distribution generator and indexer
#

use strict;
use bytes;
use lib '/home/flint/src/prime/perl5/lib';
use JSON;
use POSIX;
use Socket;
use Geo::IP;
use Net::Pcap;
use UUID::Random;
use Data::Dumper;
use Sys::Hostname;
use Sys::Syslog;
use LWP::UserAgent;
use Getopt::Long;
use Net::IPAddress;
use Net::CIDR::Lite;
use NetPacket::IP;
use NetPacket::ARP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;
use NetPacket::IGMP;
use NetPacket::Ethernet;
use NetPacket::IPv6;
#use Netpacket::ICMPv6;
use Search::Elasticsearch;

#####################################
# Prep and enable logging
#####################################
my $logging     = 0;			# Enable logging
my $logFile	= "null";		# Logfile and path
openlog("prime.pl", "ndelay,pid", "local0");

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
my $e;					# elasticsearch handle
my $bulk;				# elasticsearch bulk handle
my $cidr;
my $gi;
my $globalDst;
my $globalSrc;
my %dnscache;

#####################################
# Running config options	
#####################################
my $ip6Enable	= 1;			# Collect IPv6 details
my $l2Enable	= 1;			# Enable Layer 2 collection details 0=off 1=on.
my $l7Enable	= 1; 			# Enable Layer 7 collection details 0=off 1=on.
my $debug       = 0;			# Enable debug output

my $useTags	= 1;			# Process tag rules
my $geoip	= 1;			# Enable Geo IP records
my $datasource  = "smallroom_live";     # Source of the pcap data.

my $reverseDns	= 1;			# Enable / Disable reverse DNS lookups 0=off 1=on.
#####################################
# Options for writing results to JSON 
#####################################
my $writeFile	= 0;			# Write files out to $fileDir instead of STDOUT
my $filePath	= '/tmp/profile';	# Path to write files to
my $filePrefix	= 'profile_';		# prifix for the file names and or elastic index.
my $suffix	= '.json';

#####################################
# ElasticSearch options 
#####################################
my $elastic	= 0;			# use elasticsearch
my $esprefix	= 'profile_';
my @elNodes	= qw(192.168.4.12:9200);# elasticsearch host, and port

#####################################
# Packet Capture options 
#####################################
my $interface	= $ARGV[0]; 		# Set the interface to listen to and profile.
my $hwVendor	= 1;			# Collect the vendor for all MAC addresses found.
my $oui_file    = "/home/flint/src/prime/lib/wireshark_oui.txt";
my %oui;				# Needed to store vendor data ^^^^^^^
my $ether_file	= "/home/flint/src/prime/lib/ethertypes.csv";
my %etherTypes;				# Needed to store ether_type data ^^^^^^^
my $payload	= 1;			# Collect payload sample on or off.
my $offset	= 0;			# Starting position to collect the payload.
my $plBits	= 1500;			# Number of bits from offset start_position to collect.
my $netFilter	= 0;			# Berkley packet filters to assign to the collection.
my @targetNet	= qw( 192.168.1.0/24 );	# Subnet to to filter for.
my $sample	= 5000;			# Packet samples to process.
my $maxPerDest	= 500;			# Max packtes per destination IP to record;
my $offline	= 0;			# Offline mode for pcap file processing
my $recType	= 'all';		# Recording type: all, dist, flow, session.
my $pcapFile    = '/dev/null';
my $primaryKey;
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

if ($geoip == 1) {
	$gi = Geo::IP->open("/usr/share/GeoIP/GeoLiteCity.dat", GEOIP_STANDARD);
}

#####################################
# make sure we have the IEEE Vendor data file
# Checking if we should update.
#####################################

if ($hwVendor == 1) {
	my $epoch	  = time();
	my $oui_sched 	  = 86400; # How many seconds old does the oui.txt file need to be before we refresh it.
	my $oui_access 	  = (stat $oui_file)[9];
	my $oui_age    	  = ($epoch - $oui_access);
	if ($oui_age >= $oui_sched || !-f $oui_file) {
		`wget -O $oui_file 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'`;
	}

        open (my $oui_handle, '<', "$oui_file") or warn $!;
        while (my $line = <$oui_handle>) {
                if ($line !~ /^\#/) {
                        my($address, $vendor, $vendor_long) = split(/\t+/, $line);
			chomp($vendor_long);
                        chomp($vendor);
                        if ($vendor_long eq "") {
                                $vendor_long = $vendor;
                        }
			$address =~ s/://g;
                        $oui{$address} = $vendor_long;
                }
        }
	close($oui_file);
	$oui{FFFFFF} = "Unknown";

	my $ether_access  = (stat $ether_file)[9];
	my $ether_age     = ($epoch - $ether_access);
	if ($ether_age >= $oui_sched || !-f $ether_file) {
		`wget -O $ether_file 'https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers-1.csv'`;
	}

	open (my $ether_handle, '<', "$ether_file") or warn $!;
	while (my $line = <$ether_handle>) {
		my($eDec, $eHex, $eOct, $eDesc, $eRef) = split(/,/, $line);
		chomp($eRef);
		$etherTypes{$eDec} = $eDesc;
	}
	close($ether_handle);
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

#####################################
# Begin collection of samples.
#####################################
trafSample($interface, $sample);
closelog();

#####################################
# Process our output 
#####################################
sub output {
        my $epoch = time();
	my $indexstamp = strftime("%Y.%m.%d.%H", localtime());
	my $indexname = $esprefix.$indexstamp;

	if ($elastic == 1) {
		$e = Search::Elasticsearch->new( nodes => @elNodes );

		unless ($e->indices->exists(index => "$indexname")) {
			my $result = $e->indices->create(
				index => $indexname
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
		$ref->{$key}->{datasource} = $datasource;
		my $locaddy;
		$json->indent();
		if ($geoip == 1) {
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
					type  	=> '_doc',
					id	=> $key,
					source	=> $ref->{$key} });
			$counter++;
			if ($debug == 1) {
				my $message = "$counter documents written";
				syslog("info|local0", $message); 
				print "$message\n";
			}
		}

		if ($writeFile == 1) {
			open(FO, ">$filePath/$filePrefix$key$epoch$suffix") || die "Unable to open file in $filePath for writing.\n";
				print FO $jsonOut;
			close(FO);
		}
		if ($debug == 1) {
			print Dumper $ref->{sum};
			if ($ref->{$key}->{ip}->{ver} == 6) {
				print $jsonOut;
			}
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

	output();
}

#####################################
# Network traffic parsing 
#####################################
sub callout {
        my ($user_data, $header, $packet) = @_;

	# ETHERNET declarations
	my ($ether, $l2, $srcMac, $dstMac, $l2type);

	# ARP declarations
	my ($arpHtype, $arpProto, $arpHlen, $arpPlen, $arpOpcode, $arpSha, $arpSpa, $arpTha, $arpTpa); 

	# IP declarations
	my ($ip, $ipLen, $ipId, $ipHlen, $ipCksum, $ipTtl, $ipFoffset, $ipTos, $ipVer, $ipFlags, $ipProto, $ipSrcIp, $ipDstIp, $ipSrcIpInt, $ipDstIpInt, $ipOptions);

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
	my $eth;
	my $arp;

	# Set the time to the current minute rounded down to the first second.
	$mtime = time() - (time() % 60);
	$packetTime = strftime("%Y-%m-%dT%H:%M:%S", localtime($header->{tv_sec}));

	# Possible states are UNKNOWN, SUSPECT, CLEAN, DIRTY
	$state = "UNKNOWN";

        $ether		= NetPacket::Ethernet::strip($packet);
	$eth		= NetPacket::Ethernet->decode($packet);

	my $ethType	= $eth->{type};	

	if ($ethType == 2054) {
		# arp.htype
		# arp.ptype
		# arp.hlen
		# arp.plen
		# arp.opcode
		# arp.sha
		# arp.spa
		# arp.tha
		# arp.tpa
		$arp = NetPacket::ARP->decode($ether);
		# IANNA ARP Hardware types csv https://www.iana.org/assignments/arp-parameters/arp-parameters-2.csv
		# IANNA ARP Opcodes csv https://www.iana.org/assignments/arp-parameters/arp-parameters-1.csv
		# More IANNA reference http://www.networksorcery.com/enp/protocol/arp.htm#Source%20protocol%20address
		my $arpHtype = sprintf("0x%x", $eth_obj->{type});
		print "$arpHtype $arp_obj->{htype}\n";
		#$arpProto
		#$arpHlen
		#$arpPlen
		#$arpOpcode
		#$arpSha
		#$arpSpa
		#$arpTha
		#$arpTpa
		print Dumper($arp);
	#	print $arp_obj->{htype}.", ".$arp_obj->{proto}.", ".$arp_obj->{hlen}.", ".$arp_obj->{plen}.", ".$arp_obj->{opcode}.", ".$arp_obj->{sha}.", ".$arp_obj->{spa}.", ".$arp_obj->{tha}.", ".$arp_obj->{tpa}."\n";
	#	undef($eth_obj);
		exit;
	} else {
		#print "not arp\n";
	}

        $ip		= NetPacket::IP->decode($ether);
	#print Dumper($ip);
	$ipVer		= $ip->{ver};

	if ($ipVer == 4) {
        	$ipProto	= getprotobynumber($ip->{proto});
		$ipLen		= $ip->{len};
		$ipTtl		= $ip->{ttl};
		$ipHlen		= $ip->{hlen};
		$ipId		= $ip->{id};
		$ipOptions	= $ip->{options};
		$ipDstIp	= $ip->{dest_ip};
		$ipSrcIp	= $ip->{src_ip};
		$ipDstIpInt	= ip2num("$ip->{dest_ip}");
		$ipSrcIpInt	= ip2num("$ip->{src_ip}");
		$ipFoffset	= $ip->{foffset};
		$ipFlags	= $ip->{flags};
		$ipTos		= $ip->{tos};
		$ipCksum	= $ip->{cksum};

		$globalDst = $ipDstIp;
		$globalSrc = $ipSrcIp;

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
	}
	

	if ($ipVer == 6 && $ip6Enable == 1) {
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

		$globalDst = $ip6DstIp;
		$globalSrc = $ip6SrcIp;

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
	my $ipAddressForBeanCounter;
	if ($recType eq 'all') {
		$primaryKey = UUID::Random::generate;
		$ipAddressForBeanCounter = $globalDst;
	} elsif ($recType eq 'dist') {
		$primaryKey = $globalDst;
	}

	# Only collect N samples perl destination IP;
	$beanCounter->{$ipAddressForBeanCounter}++;
	if ($beanCounter->{$ipAddressForBeanCounter} >= $maxPerDest) {
		return;
	}

        if ($reverseDns == 1) {
                my $reverseDst;
                my $reverseSrc;

                if (exists($dnscache{$globalDst})) {
                        $reverseDst = $dnscache{$globalDst};
                } else {
                        $reverseDst = reD($globalDst);
                        $dnscache{$globalDst} = $reverseDst;
                }

                if (exists($dnscache{$globalSrc})) {
                        $reverseSrc = $dnscache{$globalSrc};
                } else {
                        $reverseSrc = reD($globalSrc);
                        $dnscache{$globalSrc} = $reverseSrc;
                }

		$ref->{$primaryKey}->{dns}->{src} = $reverseSrc;
		$ref->{$primaryKey}->{dns}->{dst} = $reverseDst;

                if ($debug == 1) {
                        print "Reverse DNS SRC: $reverseSrc\n";
                        print "Reverse DNS DST: $reverseDst\n";
                }
                        print "Reverse DNS SRC: $reverseSrc\n";
                        print "Reverse DNS DST: $reverseDst\n";
        }

	if ($l2Enable == 1) {
                $l2      = NetPacket::Ethernet->decode($packet);
		# ether.dst_mac
		# ether.src_mac
		# ether.vlan
		# ether.type
		#
		# 
                $srcMac  = $l2->{src_mac};
                $dstMac = $l2->{dest_mac};
                $srcMac  = uc($srcMac);
                $dstMac = uc($dstMac);
                $l2type  = $l2->{type};
                $ref->{$primaryKey}->{mac}->{src}  = $srcMac;
                $ref->{$primaryKey}->{mac}->{dst}  = $dstMac;
                if ($hwVendor == 1) {
                        my $srcV = substr($srcMac, 0, 6);
                        my $dstV = substr($dstMac, 0, 6);
                        if (exists($oui{$srcV})) {
                                $srcV = $oui{$srcV};
                        } else {
                                $srcV = "Unknown";
                        }

                        if (exists($oui{$dstV})) {
                                $dstV = $oui{$dstV};
                        } else {
                                $dstV = "Unknown";
                        }
                        $ref->{$primaryKey}->{src_vendor} = $srcV;
                        $ref->{$primaryKey}->{dst_vendor} = $dstV;
                        if ($debug == 1) {
                                print "$primaryKey $srcMac $srcV $dstMac $dstV\n";
                        }
                                print "$primaryKey $srcMac $srcV $dstMac $dstV\n";
                }

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
		$ref->{$primaryKey}->{ip}->{hlen} = $ipHlen;
		$ref->{$primaryKey}->{ip}->{options} = $ipOptions;
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

		unless (exists($ref->{$primaryKey}->{count}->{ip}->{hlen}->{$ipHlen})) {
			push(@{$ref->{$primaryKey}->{ip}->{hlen}}, $ipHlen);
		}
		$ref->{$primaryKey}->{count}->{ip}->{len}->{$ipLen}++;

		unless (exists($ref->{$primaryKey}->{count}->{ip}->{options}->{$ipOptions})) {
			push(@{$ref->{$primaryKey}->{ip}->{options}}, $ipOptions);
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
		$tcpOptions	= $tcp->{options};

		if ($recType eq 'all') {
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
					#$ref->{$primaryKey}->{tcp}->{data} = unpack("h$plBits", $tcp->{data});
					$ref->{$primaryKey}->{tcp}->{data} = getClean($tcp->{data});
				}
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

		# HTTP inspection module
		if ($l7Enable == 1) {
			# BGP traffic
			if ($tcp->{data} =~ /^\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff..?\x01[\x03\x04]/) {
				$ref->{$primaryKey}->{l7}->{proto} = "bgp";
                        }

			# SSH Straffic
                        if ($tcp->{data} =~ /^ssh-[12]\.[0-9]/) {
				$ref->{$primaryKey}->{l7}->{proto} = "ssh";
                        }

			# TOR Traffic
                        if ($tcp->{data} =~ /TOR1.*<identity>/) {
				$ref->{$primaryKey}->{l7}->{proto} = "tor";
                        }

			# Jabber Traffic
                        if ($tcp->{data} =~ /<stream:stream[\x09-\x0d ][ -~]*[\x09-\x0d ]xmlns=['"]jabber/) {
				$ref->{$primaryKey}->{l7}->{proto} = "jabber";
                        }

			# SSL Traffic
                        if ($tcp->{data} =~ /^(.?.?\x16\x03.*\x16\x03|.?.?\x01\x03\x01?.*\x0b)/) {
				$ref->{$primaryKey}->{l7}->{proto} = "ssl";
                        }

			# HTTP Request	
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

				#$ref->{$primaryKey}->{count}->{http}->{request}->{uri}->{$methodData[1]}++;

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
						#print "$header $headerContent\n";
					}
				}
			}
			
			# HTTP Response
			if ($tcp->{data} =~ /^HTTP\/\d/i) {
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
				if ($udp->{data}) {
					$ref->{$primaryKey}->{udp}->{data} = getClean($udp->{data});
				}
			}
			# DNS Traffic
			if (($udpSrcPort == 53 || $udpDstPort == 53) && $udp->{data} =~ /^.?.?.?.?/) {
				$ref->{$primaryKey}->{l7}->{proto} = "dns";
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
				if ($icmp->{data}) {
					$ref->{$primaryKey}->{icmp}->{data} = getClean($icmp->{data});
				}
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
				if ($igmp->{data}) {
					$ref->{$primaryKey}->{igmp}->{data} = getClean($igmp->{data});
				}
			}
		} elsif ($recType eq 'dist') {

		}
	}

	# Process Combination Strings
	#my $combo = "$ipProto:$ipLen:$ipTtl:$tcpFlag:$tcpWinsize:$tcpSrcPort:$tcpDstPort:$udpSrcPort:$udpDstPort";

	#unless (exists($ref->{$primaryKey}->{count}->{combo}->{$combo})) {
		#push(@{$ref->{$primaryKey}->{combo}}, $combo);
	#}
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
		my $getBits = $plBits;
		if ($ref->{$primaryKey}->{l7}->{proto} == "http") {
			$getBits = "2048";
		}
			
		$mess =~ s/\n|\r|\x0D/\./g;
		$mess =~ s/[^[:ascii:]]|[^[:print:]]/\./g;
		$mess = substr($mess, 0, $getBits);
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

#####################################
# Load pat files for l7 protocol idetification
#####################################

sub getPats {
	my $line;
	foreach (</etc/l7-protocols/protocols/*.pat>) {
		open(FH, "$_") || die "Unable to open $_ for reading.\n";
		foreach (<FH>) {
			$line = $_;
			chomp($line);
			unless ($line =~ /^#|^\n$/) {
				print "$line\n";
			}
		}
	}
}


#####################################
# Reverse DNS recorder
#####################################

sub reD {
	my $ip = shift;

	my $ipaddr = inet_aton($ip);
	my $hostname = gethostbyaddr($ipaddr, AF_INET);

	if (defined($hostname)) {
		return($hostname);
	} else {
		return("unknown");
	}
}
