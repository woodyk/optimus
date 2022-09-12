#!/usr/bin/perl
# Optimus packet to profile transform generator 
# network traffic distribution generator and indexer
#

use strict;
use bytes;
use lib '../lib/perl5/lib';
use JSON;
use POSIX;
use Socket;
use Geo::IP;
use Config::Tiny;
use Getopt::Long;
use Net::Pcap;
use UUID::Random;
use Data::Dumper;
use Sys::Hostname;
use Sys::Syslog;
use LWP::UserAgent;
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

my $confFile = '../etc/prime.ini';
my $config = Config::Tiny->new;
$config = Config::Tiny->read($confFile, 'utf8');
#print Dumper $config;

#####################################
# Running config options	
#####################################
my $debug       = $config->{'application'}->{'debug'}; 
my $useTags	= $config->{'application'}->{'useTags'}; 
my $dataSource  = $config->{'application'}->{'dataSource'}; 

#####################################
# Options for writing results to JSON 
#####################################
my $writeFile	= $config->{'application'}->{'writeFile'}; 
my $filePath	= $config->{'application'}->{'filePath'}; 
my $filePrefix	= $config->{'application'}->{'filePrefix'}; 
my $fileSuffix	= $config->{'application'}->{'fileSuffix'}; 
my $displayJson	= $config->{'application'}->{'displayJson'};

#####################################
# ElasticSearch options 
#####################################
my $elastic	= $config->{'application'}->{'elastic'}; 
my $esPrefix	= $config->{'application'}->{'esPrefix'}; 
my $esNode	= $config->{'application'}->{'esNode'}; 

#####################################
# Packet Capture options 
#####################################
my $interface	= $config->{'application'}->{'interface'}; 
my $hwVendor	= $config->{'application'}->{'hwVendor'}; 
my $ouiFile	= $config->{'application'}->{'ouiFile'}; 
my $ouiUrl	= $config->{'application'}->{'ouiUrl'};
my $payload	= $config->{'application'}->{'payload'}; 
my $plBits	= $config->{'application'}->{'plBits'}; 
my $netFilter	= $config->{'application'}->{'netFilter'}; 
my $targetNet	= $config->{'application'}->{'targetNet'}; 
my $sample	= $config->{'application'}->{'sample'}; 
my $maxPerDest	= $config->{'application'}->{'maxPerDest'}; 
my $ip6Enable	= $config->{'application'}->{'ip6Enable'}; 
my $l2Enable	= $config->{'application'}->{'l2Enable'};
my $l7Enable	= $config->{'application'}->{'l7Enable'}; 
my $recType	= $config->{'application'}->{'recType'}; 
my $geoip	= $config->{'application'}->{'geoip'}; 
my $geoipDat	= $config->{'application'}->{'geoipDat'};

#####################################
# Prep and enable logging
#####################################
my $logging     = $config->{'application'}->{'logging'}; 

# Time to declare your items
my $ref; 				# data container for all the collected samples
my $beanCounter;			# packet counter
my $e;					# elasticsearch handle
my $bulk;				# elasticsearch bulk handle
my $cidr;
my $gi;
my %oui;
my $primaryKey;
my $offline;
my $message;
my $counter;
my $pcapFile;

# Get command line options.
GetOptions(
        'interface=s'   => \$interface,
        'pcap=s'        => \$pcapFile,
        'json!'         => sub { $displayJson = 1; },
	'debug!'	=> sub { $debug = 1; },
	'count=i'	=> \$sample,
	'help!'		=> \&help,
	'elastic'	=> sub { $elastic = 1},
	'server=s'	=> \$esNode,
	'logging'	=> sub { $logging = 1},
);

logIt("started.");

if ($esNode !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}$/) {
	$message = "error: IP address not valid.\n";
	print "$message";
	debugOut($message);
	logIt($message);
	exit;
} 

$ENV{TZ} = 'UTC';
my $hostname = hostname();

#tcp flags: urg, ack, psh, rst, syn, fin, ece, cwr
#my @NetPacketIP = qw( ver hlen flags foffset tos len id ttl proto cksum src_ip dest_ip options data );
#my @NetPacketTCP = qw( src_port dest_port seqnum acknum hlen reserved flags winsize cksum urg options data );
#my @NetPacketICMP = qw( type code cksum data );
#my @NetPacketIGMP = qw( version type len subtype cksum group_addr data );
#my @NetPacketUDP = qw( src_port dest_port len cksum data );
#my @NetPacketEthernet = qw( src_mac dest_mac type data ); 
#my @NetPacketARP = qw( htype proto hlen plen opcode sha spa tha tpa );


#####################################
# Overwrite Variables with Environment Settings if they exist.	
#####################################

if ($ENV{OPTIMUS_INTERFACE}) {
	$interface = $ENV{OPTIUMUS_INTERFACE};
}

if ($netFilter == 1) {
	$cidr = Net::CIDR::Lite->new;
	$cidr->add($targetNet);
	#foreach (@targetNet) {
	#	$cidr->add($_);
	#}
}

#####################################
# Open Geo IP handle if enabled. 
#####################################

if ($geoip == 1) {
	$gi = Geo::IP->open($geoipDat, GEOIP_STANDARD);
}

#####################################
# make sure we have the IEEE Vendor data file
# Checking if we should update.
#####################################

if ($hwVendor == 1) {
	my $epoch	  = time();
	my $oui_sched 	  = 86400; # How many seconds old does the oui.txt file need to be before we refresh it.
	my $oui_access 	  = (stat $ouiFile)[9];
	my $oui_age    	  = ($epoch - $oui_access);
	if ($oui_age >= $oui_sched || !-f $ouiFile) {
		`wget -O $ouiFile $ouiUrl`
	}

        open (my $oui_handle, '<', "$ouiFile") or warn $!;
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
	close($ouiFile);
	$oui{FFFFFF} = "Unknown";
}

#####################################
# Sanity checks 
#####################################

# Check that a file has been given if running in offline mode
if (defined($pcapFile)) {
	if (!-e $pcapFile) {
		$message = "Unable to find file $pcapFile for processing.\n";
		print "$message";
		logIt($message);
		exit;
	} else {
		$sample = -1;
		$offline = 1;
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
	my $indexname = $esPrefix.$indexstamp;

	if ($elastic == 1) {
		$e = Search::Elasticsearch->new( nodes => $esNode ); 

		unless ($e->indices->exists(index => "$indexname")) {
			my $result = $e->indices->create(
				index => $indexname
			);
		}
		$bulk = $e->bulk_helper( max_count => 100,
					 max_time  => 300 );
	}

	$counter = 0;
	my $result;
	foreach my $key (keys(%{$ref})) {
		my $json = JSON->new();	

		my $hashSize = keys($ref->{$key});
		if ($hashSize <= 1) {
			next;
		}
		
		$ref->{$key}->{hostname} = $hostname;
		$ref->{$key}->{int} = $interface;
		$ref->{$key}->{datasource} = $dataSource;
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
			$counter++;	
		}
			
		my $jsonOut = $json->utf8->encode($ref->{$key});
		if ($elastic == 1) {
			$bulk->create({ index 	=> $indexname,
					type  	=> '_doc',
					id	=> $key,
					source	=> $ref->{$key} });
			my $message = "$counter elasticsearch documents written";
			debugOut($message);

		}

		if ($displayJson == 1) {
			print "$jsonOut\n";
		}

		if ($writeFile == 1) {
			if (!-d $filePath) {
				mkdir($filePath, 0755);
			}
			open(FO, ">$filePath/$filePrefix$key$epoch$fileSuffix") || die "Unable to open file in $filePath for writing.\n";
				print FO $jsonOut;
			close(FO);
		}
	}
	if ($elastic == 1) {
		$result = $bulk->flush;
		$message = "Wrote $counter packets to elasticsearch\n";
		print "$message";
		logIt($message);
	}
	undef($ref);
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
                warn "Unable to capture traffic.\n$err\n";
		exit;
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
	my $eth_obj;

	# Set the time to the current minute rounded down to the first second.
	$mtime = time() - (time() % 60);
	$packetTime = strftime("%Y-%m-%dT%H:%M:%S", localtime($header->{tv_sec}));
	$ref->{$primaryKey}->{date} = $packetTime;

	$message = "date:$ref->{$primaryKey}->{date}\n";
	debugOut($message);

	# Possible states are UNKNOWN, SUSPECT, CLEAN, DIRTY
	$state = "UNKNOWN";

        $ether		= NetPacket::Ethernet::strip($packet);
	$eth_obj	= NetPacket::Ethernet->decode($packet);

	# decimal number for ARP 2054:
	my $is_arp = 0;
	if ($eth_obj->{type} == "2054") {
		my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);

		$arpHtype  = $arp_obj->{htype};
		$arpProto  = $arp_obj->{proto};
		$arpHlen   = $arp_obj->{hlen};
		$arpOpcode = $arp_obj->{opcode};
		$arpSha    = uc($arp_obj->{sha});
		$arpSpa    = uc($arp_obj->{spa});
		$arpTha    = uc($arp_obj->{tha});
		$arpTpa    = uc($arp_obj->{tpa});
		
		$is_arp = 1;
	}

	$ip		= NetPacket::IP->decode($ether);
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

		$message = "IPv4 data:\n\tip.src:$ipSrcIp\n\tip.dst:$ipDstIp\n\tip.proto:$ipProto\n\tip.len:$ipLen\n\tip.ttl:$ipTtl\n\tip.hlen:$ipHlen\n\tip.options:$ipOptions\n\tip.offset:$ipFoffset\n\tip.flags:$ipFlags\n\tip.tos:$ipTos\n\tip.version:$ipVer\n\tip.cksum:$ipCksum\n";
		debugOut($message);
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

	}
	
	if ($netFilter == 1) {
		if (!$cidr->find($ipDstIp) && !$cidr->find($ipSrcIp) ) {
                        return;
                }
        }

	# Primary key that determines indexing resolution.
	my $ipAddressForBeanCounter;
	$primaryKey = UUID::Random::generate;
	if ($ipVer == 6) {
		$ipAddressForBeanCounter = $ip6DstIp;
	} else {
		$ipAddressForBeanCounter = $ipDstIp;
	}
	if ($recType eq 'dist') {
		if ($ipVer == 6) {
			$primaryKey = $ip6DstIp;
		} else {
			$primaryKey = $ipDstIp;
		}
	}

	# Only collect N samples perl destination IP;
	$beanCounter->{$ipAddressForBeanCounter}++;
	if ($maxPerDest > 0 && $beanCounter->{$ipAddressForBeanCounter} >= $maxPerDest) {
		return;
	}

        if ($l2Enable == 1) {
                $l2      = NetPacket::Ethernet->decode($packet);
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

			$message = "\tVendor data:\n\t\tprimarykey:$primaryKey\n\t\tmac.src:$srcMac\n\t\tmac.dst:$dstMac\n\t\tsrc_vendor:$srcV\n\t\tdst_vendor:$dstV\n";
			debugOut($message);
                }
           
		if ($is_arp == 1) {             
			$ref->{$primaryKey}->{l2}->{proto}   = "arp";
			$ref->{$primaryKey}->{arp}->{htype}  = $arpHtype;
			$ref->{$primaryKey}->{arp}->{proto}  = $arpProto;
			$ref->{$primaryKey}->{arp}->{hlen}   = $arpHlen;
			$ref->{$primaryKey}->{arp}->{opcode} = $arpOpcode;
			$ref->{$primaryKey}->{arp}->{sha}    = $arpSha;
			$ref->{$primaryKey}->{arp}->{spa}    = $arpSpa;
			$ref->{$primaryKey}->{arp}->{tha}    = $arpTha;
			$ref->{$primaryKey}->{arp}->{tpa}    = $arpTpa;

			$message = "ARP data:\n\tl2.proto:$ref->{$primaryKey}->{l2}->{proto}\n\tarp.htype:$arpHtype\n\tarp.proto:$arpProto\n\tarp.hlen:$arpHlen\n\tarp.opcode:$arpOpcode\n\tarp.sha:$arpSha\n\tarp.spa:$arpSpa\n\tarp.tha:$arpTha\n\tarp.tpa:$arpTpa\n";
			debugOut($message);

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

		$message = "IPv6 data:\n\tip6.src:$ip6SrcIp\n\tip6.dst:$ip6DstIp\n\tip6.class:$ip6Class\n\tip6.flow:$ip6Flow\n\tip6.plen:$ip6Plen\n\tip6.nxt:$ip6Nxt $ipProto\n\tip6.hlim:$ip6Hlim\n";
		debugOut($message);


	}


	# IPv4 Assignment Tagging
	if ($ipDstIp =~ /255/ || $ipSrcIp =~ /255/) {
		addTag($primaryKey, 'BROADCAST');
	}
	if ($ipDstIp =~ /^22[3-9]|^23[0-9]/ || $ipSrcIp =~ /^22[3-9]|^23[0-9]/ ) { 	#223 - 239 = Multicast
		addTag($primaryKey, 'MULTICAST');
	}

	#$ref->{$primaryKey}->{packets}++;

	$ref->{$primaryKey}->{ip}->{dst} = $ipDstIp;
	$ref->{$primaryKey}->{ip}->{src} = $ipSrcIp;
	$ref->{$primaryKey}->{raw}->{ip}->{dst} = $ipDstIp;
	$ref->{$primaryKey}->{raw}->{ip}->{src} = $ipSrcIp;
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

	if ($recType eq 'dist') {	

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

		if ($recType eq 'dist') {
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

		# L7 inspection modules
		if ($l7Enable == 1) {
			# BGP traffic
			if ($tcp->{data} =~ /^\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff..?\x01[\x03\x04]/) {
				$ref->{$primaryKey}->{l7}->{proto} = "bgp";
                        }

			# SSH Straffic
                        if ($tcp->{data} =~ /^ssh-[12]\.[0-9]/i) {
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
				my $methUri = shift(@lines);
				my @methodData = split(" ", $methUri);

				$ref->{$primaryKey}->{l7}->{proto} = 'http';
				$ref->{$primaryKey}->{http}->{request}->{method} = $methodData[0];
				$ref->{$primaryKey}->{http}->{request}->{uri} = $methodData[1];
				$ref->{$primaryKey}->{http}->{request}->{version} = $methodData[2];

				$message = "\tLayer7 data:\n\t\thttp.request.method:$ref->{$primaryKey}->{http}->{request}->{method}\n\t\thttp.request.uri:$ref->{$primaryKey}->{http}->{request}->{uri}\n\t\thttp.request.version:$ref->{$primaryKey}->{http}->{request}->{version}\n"; 
				debugOut($message);

				if ($recType eq 'dist') {
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

					$ref->{$primaryKey}->{http}->{header}->{$header} = $headerContent;

					$message = "\t\thttp.header:$ref->{$primaryKey}->{http}->{header}->{$header}\n";
					debugOut($message);

					if ($recType eq "dist") {
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

				$ref->{$primaryKey}->{l7}->{proto} = 'http';
				$ref->{$primaryKey}->{http}->{response}->{version} = $resVersion;
				$ref->{$primaryKey}->{http}->{response}->{code} = $resCode;
				$ref->{$primaryKey}->{http}->{response}->{status} = $resStatus;

				$message = "\t\thttp.response.version:$ref->{$primaryKey}->{http}->{response}->{version}\n\t\thttp.response.code:$ref->{$primaryKey}->{http}->{response}->{code}\n\t\thttp.response.status:$ref->{$primaryKey}->{http}->{response}->{status}\n";
				debugOut($message);

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
		# DNS Traffic
		if (($udpSrcPort == 53 || $udpDstPort == 53) && $udp->{data} =~ /^.?.?.?.?[\x01\x02].?.?.?.?.?.?/) {
			$ref->{$primaryKey}->{l7}->{proto} = "dns";
                }

		if ($recType eq 'dist') {
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

		$message = "\tUDP data:\n\t\tudp.dstport:$ref->{$primaryKey}->{udp}->{dstport}\n\t\tudp.srcport:$ref->{$primaryKey}->{udp}->{srcport}\n\t\tudp.len:$ref->{$primaryKey}->{udp}->{len}\n";
		debugOut($message);
	
	
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

		if ($recType eq 'dist') {

		}

		$message =  "\tICMP data:\n\t\ticmp.type:$ref->{$primaryKey}->{icmp}->{type}\n\t\ticmp.code:$ref->{$primaryKey}->{icmp}->{code}\n\t\ticmp.data:$ref->{$primaryKey}->{icmp}->{data}\n";
		debugOut($message);

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

		if ($recType eq 'dist') {

		}

		$message = "\tIGMP data:\n\t\tigmp.version:$ref->{$primaryKey}->{igmp}->{version}\n\t\tigmp.type:$ref->{$primaryKey}->{igmp}->{type}\n\t\tigmp.len:$ref->{$primaryKey}->{igmp}->{len}\n\t\tigmp.subtype:$ref->{$primaryKey}->{igmp}->{subtype}\n\t\tigmp.group_addr:$ref->{$primaryKey}->{igmp}->{group_addr}\n\t\tigmp.data:$ref->{$primaryKey}->{igmp}->{data}\n";
		debugOut($message);

	}

	$message = "\tl7.proto:$ref->{$primaryKey}->{l7}->{proto}\n";
	debugOut($message);

	# Process Combination Strings
	#my $combo = "$ipProto:$ipLen:$ipTtl:$tcpFlag:$tcpWinsize:$tcpSrcPort:$tcpDstPort:$udpSrcPort:$udpDstPort";

	#unless (exists($ref->{$primaryKey}->{count}->{combo}->{$combo})) {
		#push(@{$ref->{$primaryKey}->{combo}}, $combo);
	#}
}
logIt("stopped. $counter packets processed.");


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
		$message = "TAG:\t$tag\n";
		debugOut($message);
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
		#if ($ref->{$primaryKey}->{l7}->{proto} == "http") {
		#	$getBits = "2048";
		#}
			
		$mess =~ s/\n|\r|\x0D/\./g;
		$mess =~ s/[^[:ascii:]]|[^[:print:]]/\./g;
		$mess = substr($mess, 0, $getBits);
	} else {
		$mess = "";
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
# log the message given 
#####################################
sub logIt {
	my $message = shift;
	if ($logging == 1) {
		openlog("$0", "ndelay,pid", "local0");
		syslog("info|local0", $message);
		closelog();
	}
}

#####################################
# print message to stdout for debug 
#####################################
sub debugOut {
	my $message = shift;
	if ($debug == 1) {
		print "$message";
	}
}


#####################################
# help output 
#####################################
sub help {
	print "$0\n";
	print "\t-i\tInterface to listen to.\n";
	print "\t-p\tPath to pcap file for reading.\n";
	print "\t-j\tOuput JSON to STDOUT for each packet.\n";
	print "\t-d\tOutput debug information to STDOUT.\n";
	print "\t-c\tNumber of packets to process. Only works when interface is defined.\n";
	print "\t-e\tEnable elastic search.\n";
	print "\t-s\tElastic search server address with port. eg: 192.168.1.10:9200\n";
	print "\t-l\tEnable syslog logging.\n";
	print "\t-h\tThis help output.\n";
	print "\n";
	print "Examples:\n";
	print "\tListen to eth0 for 10 packets and output JSON.\n";
	print "\t$0 -i eth0 -c 10 =j\n";
	print "\n";
	print "\tRead from pcap file and output JSON.\n";
	print "\t$0 -p /path/to/pcap -j\n";
	print "\n";
	print "\tListen to eth0 for 1000 packets and inject data to elasticsearch.\n";
	print "\t$0 -i eth0 -c 1000 -e -s 192.168.0.10:9200\n";
	print "\n";
	
	exit;
}

