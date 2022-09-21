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

my $confFile = '../etc/optimus.ini';
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
my $targetNet	= $config->{'application'}->{'targetNet'}; 
my $sample	= $config->{'application'}->{'sample'}; 
my $maxPerDest	= $config->{'application'}->{'maxPerDest'}; 
my $ip6Enable	= $config->{'application'}->{'ip6Enable'}; 
my $l2Enable	= $config->{'application'}->{'l2Enable'};
my $l7Enable	= $config->{'application'}->{'l7Enable'}; 
my $geoip	= $config->{'application'}->{'geoip'}; 
my $geoipDat	= $config->{'application'}->{'geoipDat'};
my $nameLookup	= $config->{'application'}->{'nameLookup'};

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
	'revlookup'	=> sub { $nameLookup = 1; },
);

logIt("started.");

if ($esNode !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}$/) {
	$message = "error: IP address not valid.\n";
	print "$message";
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
		`wget -O $ouiFile $ouiUrl`;
	}

        open (OUI, '<', "$ouiFile") or warn $!;
        foreach my $line (<OUI>) {
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
	close(OUI);
	$oui{FFFFFF} = "Unknown";
}

#####################################
# Check that a file has been given if running in offline mode
#####################################

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

		my $hashSize = length($ref->{$key});
		if ($hashSize <= 1) {
			next;
		}
		
		$ref->{$key}->{hostname} = $hostname;
		$ref->{$key}->{int} = $interface;
		$ref->{$key}->{datasource} = $dataSource;

		my $srcAddy;
		my $dstAddy;

		if ($ref->{$key}->{ip}->{ver} == 4) {
			$srcAddy = $ref->{$key}->{ip}->{src};
			$dstAddy = $ref->{$key}->{ip}->{dst};
		} elsif ($ref->{$key}->{ip}->{ver} == 6) {
			$srcAddy = $ref->{$key}->{ip6}->{src};
			$dstAddy = $ref->{$key}->{ip6}->{dst};
		}

		$json->indent();
		if ($geoip == 1) {
			if (my $record = $gi->record_by_addr("$srcAddy")) {
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

		if ($nameLookup == 1) {	
			$ref->{$key}->{dns}->{src} = revDns($srcAddy);
			$ref->{$key}->{dns}->{dst} = revDns($dstAddy);
		}
			
		my $jsonOut = $json->utf8->encode($ref->{$key});
		if ($elastic == 1) {
			$bulk->create({ index 	=> $indexname,
					type  	=> '_doc',
					id	=> $key,
					source	=> $ref->{$key} });
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

	# IP declarations
	my ($ip, $ipProto, $ipSrcIp, $ipDstIp);

	# IPv6 declarations
	my $ip6;

	# TCP delcarations
	my ($tcp, $tcpFlag);

	# UDP declarations
	my $udp;

	# ICMP declarations
	my $icmp;

	# IGMP declarations
	my $igmp;

	# Other declarations for sub callout
	my $state;
	my $packetTime;
	my $mtime;
	my $eth_obj;

	# Set the time to the current minute rounded down to the first second.
	$mtime = time() - (time() % 60);
	$packetTime = strftime("%Y-%m-%dT%H:%M:%S", localtime($header->{tv_sec}));
	$ref->{$primaryKey}->{date} = $packetTime;

	# Possible states are UNKNOWN, SUSPECT, CLEAN, DIRTY
	$state = "UNKNOWN";

        $ether		= NetPacket::Ethernet::strip($packet);
	$eth_obj	= NetPacket::Ethernet->decode($packet);

	# decimal number for ARP 2054:
	if ($eth_obj->{type} == "2054" && $l2Enable == 1) {
		my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);

		$ref->{$primaryKey}->{l2}->{proto}   = "arp";
		$ref->{$primaryKey}->{arp}->{htype}  = $arp_obj->{htype};
		$ref->{$primaryKey}->{arp}->{proto}  = $arp_obj->{proto};
		$ref->{$primaryKey}->{arp}->{hlen}   = $arp_obj->{hlen};
		$ref->{$primaryKey}->{arp}->{opcode} = $arp_obj->{opcode};
		$ref->{$primaryKey}->{arp}->{sha}    = uc($arp_obj->{sha});
		$ref->{$primaryKey}->{arp}->{spa}    = uc($arp_obj->{spa});
		$ref->{$primaryKey}->{arp}->{tha}    = uc($arp_obj->{tha});
		$ref->{$primaryKey}->{arp}->{tpa}    = uc($arp_obj->{tpa});

	}

	$ip		= NetPacket::IP->decode($ether);

	if ($ip->{ver} == 4) {
		$ipProto        = getprotobynumber($ip->{proto});
		$ref->{$primaryKey}->{ip}->{dst} 	= $ip->{dest_ip};
		$ref->{$primaryKey}->{ip}->{src} 	= $ip->{src_ip};
		$ref->{$primaryKey}->{raw}->{ip}->{dst} = $ip->{dest_ip};
		$ref->{$primaryKey}->{raw}->{ip}->{src} = $ip->{src_ip};
		$ref->{$primaryKey}->{ip}->{ver} 	= $ip->{ver};
		$ref->{$primaryKey}->{ip}->{foffset} 	= $ip->{foffset};
		$ref->{$primaryKey}->{ip}->{tos} 	= $ip->{tos};
		$ref->{$primaryKey}->{ip}->{flags} 	= $ip->{flags};
		$ref->{$primaryKey}->{ip}->{len} 	= $ip->{len};
		$ref->{$primaryKey}->{ip}->{hlen} 	= $ip->{hlen};
		$ref->{$primaryKey}->{ip}->{options} 	= $ip->{options};
		$ref->{$primaryKey}->{ip}->{ttl} 	= $ip->{ttl};
		$ref->{$primaryKey}->{ip}->{proto} 	= $ipProto;
		$ref->{$primaryKey}->{ip}->{cksum} 	= $ip->{cksum};

		# IPv4 Assignment Tagging       
                if ($ref->{$primaryKey}->{ip}->{src} =~ /^255/ ||  $ref->{$primaryKey}->{ip}->{dst} =~ /^255/) {
                        addTag($primaryKey, 'BROADCAST');
                } elsif ($ref->{$primaryKey}->{ip}->{src} =~ /^22[3-9]|^23[0-9]/ || $ref->{$primaryKey}->{ip}->{dst} =~ /^22[3-9]|^23[0-9]/ ) {      #223 - 239 = Multicast
                        addTag($primaryKey, 'MULTICAST');
                }

	}
	

	if ($ip->{ver} == 6 && $ip6Enable == 1) {
  		$ip6 = NetPacket::IPv6->decode($ether);

		$ref->{$primaryKey}->{ip6}->{src}       = $ip6->{src_ip};
                $ref->{$primaryKey}->{ip6}->{dst}       = $ip6->{dest_ip};
                $ref->{$primaryKey}->{raw}->{ip}->{src} = $ip6->{src_ip};
                $ref->{$primaryKey}->{raw}->{ip}->{dst} = $ip6->{dest_ip};
                $ref->{$primaryKey}->{ip6}->{class}     = $ip6->{class};
                $ref->{$primaryKey}->{ip6}->{flow}      = $ip6->{flow};
                $ref->{$primaryKey}->{ip6}->{plen}      = $ip6->{plen};
                $ref->{$primaryKey}->{ip6}->{nxt}       = $ip6->{nxt};
                $ref->{$primaryKey}->{ip6}->{hlim}      = $ip6->{hlim};
        	$ipProto = getprotobynumber($ip6->{nxt});

	}
	
	# Primary key that determines indexing resolution.
	my $ipAddressForBeanCounter;
	$primaryKey = UUID::Random::generate;
	if ($ip->{ver} == 6) {
		$ipAddressForBeanCounter = $ref->{$primaryKey}->{ip6}->{dst};
	} elsif ($ip->{ver} == 4) {
		$ipAddressForBeanCounter = $ipDstIp;
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
                        $ref->{$primaryKey}->{vendor}->{src} = $srcV;
                        $ref->{$primaryKey}->{vendor}->{dst} = $dstV;

                }
           
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
		
		$ref->{$primaryKey}->{tcp}->{reserved}		= $tcp->{reserved};
		$ref->{$primaryKey}->{tcp}->{cksum}		= $tcp->{cksum};
		$ref->{$primaryKey}->{tcp}->{urg}		= $tcp->{urg};
		#$ref->{$primaryKey}->{tcp}->{options}		= $tcp->{options};
		$ref->{$primaryKey}->{tcp}->{acknum}		= $tcp->{acknum};
		$ref->{$primaryKey}->{tcp}->{flags}		= $tcpFlag;
		$ref->{$primaryKey}->{tcp}->{hlen}		= $tcp->{hlen};
		$ref->{$primaryKey}->{tcp}->{dstport}		= $tcp->{dest_port};
		$ref->{$primaryKey}->{tcp}->{srcport}		= $tcp->{src_port};
		$ref->{$primaryKey}->{tcp}->{seq}		= $tcp->{seqnum};
		$ref->{$primaryKey}->{tcp}->{window_size}	= $tcp->{winsize};

		if ($payload == 1) {
			if ($tcp->{data}) {
				$ref->{$primaryKey}->{tcp}->{data} = getClean($tcp->{data});
			}
		}

		# L7 inspection modules
		if ($l7Enable == 1) {
			# BGP traffic
			if ($tcp->{data} =~ /^\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff..?\x01[\x03\x04]/) {
				$ref->{$primaryKey}->{l7}->{proto} = "bgp";
                        }

			# SSH Straffic
                        if ($ref->{$primaryKey}->{tcp}->{dstport} == 22 || $ref->{$primaryKey}->{tcp}->{srcport} == 22 || $tcp->{data} =~ /^ssh-[12]\.[0-9]/i) {
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
                        if ($tcp->{data} =~ /^(.?.?\x16\x03.*\x16\x03|.?.?\x01\x03\x01?.*\x0b)|(3t.?.?.?.?.?.?.?.?.?.?h2.?http\/1\.1.?.?)/) {
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
		$ref->{$primaryKey}->{udp}->{dstport}	= $udp->{dest_port};
		$ref->{$primaryKey}->{udp}->{srcport}	= $udp->{src_port};
		$ref->{$primaryKey}->{udp}->{len}	= $udp->{len};

		if ($payload == 1) {
			if ($udp->{data}) {
				$ref->{$primaryKey}->{udp}->{data} = getClean($udp->{data});
			}
		}
		# DNS Traffic
		if ($ref->{$primaryKey}->{udp}->{dstport} == 53 || $ref->{$primaryKey}->{udp}->{srcport} == 53 || $udp->{data} =~ /^.?.?.?.?[\x01\x02].?.?.?.?.?.?/) {
			$ref->{$primaryKey}->{l7}->{proto} = "dns";
                }

        } elsif ($ipProto eq "icmp") {
        	$icmp = NetPacket::ICMP->decode($ip->{data});
		$ref->{$primaryKey}->{icmp}->{type} = $icmp->{type};
		$ref->{$primaryKey}->{icmp}->{code} = $icmp->{code};

		if ($payload == 1) {
			if ($icmp->{data}) {
				$ref->{$primaryKey}->{icmp}->{data} = getClean($icmp->{data});
			}
		}

	} elsif ($ipProto eq "igmp") {
        	$igmp = NetPacket::IGMP->decode($ip->{data});
		$ref->{$primaryKey}->{igmp}->{version}		= $igmp->{version};
		$ref->{$primaryKey}->{igmp}->{type}		= $igmp->{type};
		$ref->{$primaryKey}->{igmp}->{len}		= $igmp->{len};
		$ref->{$primaryKey}->{igmp}->{subtype}		= $igmp->{subtype};
		$ref->{$primaryKey}->{igmp}->{group_addr}	= $igmp->{group_addr};

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
	print "\t-r\tEnable reverse DNS lookup. (much slower)\n";
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

#####################################
# Reverse DNS recorder
#####################################

sub revDns {
	my $ip = shift;

	my $ipaddr = inet_aton($ip);
	my $hostname = gethostbyaddr($ipaddr, AF_INET);

	if (defined($hostname)) {
		return($hostname);
	} else {
		return("unknown");
	}
}

