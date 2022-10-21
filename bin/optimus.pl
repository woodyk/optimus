#!/usr/bin/perl
# Optimus packet to profile transform generator 
# network traffic distribution generator and indexer
#

use warnings;
use strict;
use bytes;
use lib '../lib/perl5/lib';
use JSON;
use POSIX;
use Socket;
use Config::Tiny;
use Getopt::Long;
use Net::Pcap;
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

my $confFile = '../etc/optimus.ini';
my $Config = Config::Tiny->new;
my $config = Config::Tiny->read($confFile, 'utf8');
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
my $sample	= $config->{'application'}->{'sample'}; 
my $maxPerDest	= $config->{'application'}->{'maxPerDest'}; 
my $ip6Enable	= $config->{'application'}->{'ip6Enable'}; 
my $l2Enable	= $config->{'application'}->{'l2Enable'};
my $l7Enable	= $config->{'application'}->{'l7Enable'}; 
my $geoIp	= $config->{'application'}->{'geoIp'}; 
my $geoIpDb	= $config->{'application'}->{'geoIpDb'};
my $nameLookup	= $config->{'application'}->{'nameLookup'};

#####################################
# Prep and enable logging
#####################################
my $logging     = $config->{'application'}->{'logging'}; 
my $retention	= $config->{'application'}->{'retention'};

# Time to declare your items
my $ref; 				# data container for all the collected samples
my $beanCounter;			# packet counter
my $e;					# elasticsearch handle
my $bulk;				# elasticsearch bulk handle
my $gi;
my %oui;
my $primaryKey;
my $offline = 0;
my $message;
my $counter;
my $pcapFile;
my %patterns;
my $geoIpType;

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

local $ENV{TZ} = 'UTC';
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
if ($geoIp == 1) {
	$gi = MaxMind::DB::Reader->new(file => $geoIpDb);
	$geoIpType = "mmdb";
}

#####################################
# make sure we have the IEEE Vendor data file
# Checking if we should update.
#####################################

if ($hwVendor == 1) {
	my $oui_access;
	my $oui_age;
	my $epoch	  = time();
	my $oui_sched 	  = 86400; # How many seconds old does the oui.txt file need to be before we refresh it.
	if (-e $ouiFile) {
		$oui_access 	  = (stat $ouiFile)[9];
		$oui_age    	  = ($epoch - $oui_access);
	}

	if ($oui_age >= $oui_sched || !-f $ouiFile) {
		my $chld_in;
		my $pid = open3($chld_in, '>&STDOUT', '>&STDERR', "wget -O $ouiFile $ouiUrl") or die "Unable to execute command: $!\n";
		waitpid($pid, 0);
	}

        open(my $OUI, '<', "$ouiFile") or warn $!;
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

#if ($l7Enable == 1) {
#	getPats();
#}

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
		if ($esNode !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}$/) {
        		$message = "error: IP address not valid.\n";
        		print "$message";
        		logIt($message);
        		exit;
		}
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
		$counter++;	
		
		$ref->{$key}->{hostname} = $hostname;
		$ref->{$key}->{interface} = $interface;
		$ref->{$key}->{datasource} = $dataSource;

		$json->indent();
		if ($geoIp == 1) {
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

		if ($nameLookup == 1) {	
			$ref->{$key}->{dns}->{src} = revDns($ref->{$key}->{ip}->{src});
			$ref->{$key}->{dns}->{dst} = revDns($ref->{$key}->{ip}->{dst});
		}
			
		if ($elastic == 1) {
			$bulk->create({ index 	=> $indexname,
					id	=> $key,
					source	=> $ref->{$key} });
		}

		my $jsonOut = $json->utf8->encode($ref->{$key});

		if ($displayJson == 1) {
			print "$jsonOut\n";
		}

		if ($writeFile == 1) {
			if (!-d $filePath) {
				mkdir($filePath, 0755);
			}
			open(my $FO, '>', "$filePath/$filePrefix$key$epoch$fileSuffix") || die "Unable to open file in $filePath for writing.\n";
				print $FO $jsonOut;
			close($FO);
		}
	}
	if ($elastic == 1) {
		$result = $bulk->flush;
		$message = "Wrote $counter packets to elasticsearch\n";
		print "$message";
		logIt($message);
		if ($retention > 0) {
			cleanIndex($retention);
		}
	}
	undef($ref);

	return;
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

	return;
}

#####################################
# Network traffic parsing 
#####################################
sub callout {
        my ($user_data, $header, $packet) = @_;

	# ETHERNET declarations
	my ($ether, $l2, $srcMac, $dstMac, $l2type);

	# IP declarations
	my $ip;

	# IPv6 declarations
	my $ip6;

	# TCP delcarations
	my ($tcp, $tcpFlag);

	# UDP declarations
	my $udp;

	# ICMP declarations
	my ($icmp, $icmpV6);

	# IGMP declarations
	my $igmp;

	# Other declarations for sub callout
	my $packetTime;
	my $mtime;
	my $eth_obj;

	# Assign a unique UUID for this packet.
	my $uuidBin = create_uuid(UUID_RANDOM);
	$primaryKey = uuid_to_string($uuidBin);

	$ref->{$primaryKey}->{uuid} = $primaryKey;

        my $ipAddressForBeanCounter = "UNKNOWN";
	my $ipProto = "UNKNOWN";
	$ref->{$primaryKey}->{protos}->{l2}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l3}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l4}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l5}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l6}   = "unknown";
	$ref->{$primaryKey}->{protos}->{l7}   = "unknown";

	# Set the time to the current minute rounded down to the first second.
	$mtime = time() - (time() % 60);
	$packetTime = strftime("%Y-%m-%dT%H:%M:%S", localtime($header->{tv_sec}));
	$ref->{$primaryKey}->{date} = $packetTime;

        $ether		= NetPacket::Ethernet::strip($packet);
	$eth_obj	= NetPacket::Ethernet->decode($packet);

	# decimal number for ARP 2054:

	if ($l2Enable == 1) {
		if ($eth_obj->{type} == "2054") {
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
	
		} elsif ($eth_obj->{type} == "2048") {
			$ref->{$primaryKey}->{protos}->{l2} = "ip_route";

		}
	}

	$ip = NetPacket::IP->decode($ether);

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
		$ref->{$primaryKey}->{ip}->{options} 	= $ip->{options};
		$ref->{$primaryKey}->{ip}->{ttl} 	= $ip->{ttl};
		$ref->{$primaryKey}->{ip}->{cksum} 	= $ip->{cksum};
		$ref->{$primaryKey}->{ip}->{ver} 	= $ip->{ver};
		$ipAddressForBeanCounter = $ref->{$primaryKey}->{ip}->{dst};

		# IPv4 Assignment Tagging       
                if ($ref->{$primaryKey}->{ip}->{src} =~ /^255/ ||  $ref->{$primaryKey}->{ip}->{dst} =~ /^255/) {
                        addTag($primaryKey, 'BROADCAST');
                } elsif ($ref->{$primaryKey}->{ip}->{src} =~ /^22[3-9]|^23[0-9]/ || $ref->{$primaryKey}->{ip}->{dst} =~ /^22[3-9]|^23[0-9]/ ) {      #223 - 239 = Multicast
                        addTag($primaryKey, 'MULTICAST');
                }

	}
	

	if ($ip->{ver} == 6 && $ip6Enable == 1) {

		$ref->{$primaryKey}->{protos}->{l3} = "ipv6";

  		$ip6 = NetPacket::IPv6->decode($ether);

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
                        $ref->{$primaryKey}->{mac}->{src_vendor} = $srcV;
                        $ref->{$primaryKey}->{mac}->{dst_vendor} = $dstV;

                }
           
        }

	
        if ($ipProto eq "tcp") {
        	$tcp = NetPacket::TCP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l4} = "tcp";

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
				$ref->{$primaryKey}->{protos}->{l7} = "bgp";
                        }

			# SSH Straffic
                        if ($ref->{$primaryKey}->{tcp}->{dstport} == 22 || $ref->{$primaryKey}->{tcp}->{srcport} == 22 || $tcp->{data} =~ /^ssh-[12]\.[0-9]/i) {
				$ref->{$primaryKey}->{protos}->{l7} = "ssh";
                        }

			# SSL Traffic
                        if ($tcp->{data} =~ /^(.?.?\x16\x03.*\x16\x03|.?.?\x01\x03\x01?.*\x0b)|(3t.?.?.?.?.?.?.?.?.?.?h2.?http\/1\.1.?.?)/) {
				$ref->{$primaryKey}->{protos}->{l7} = "ssl";
                        }

			# HTTP Request	
			if ($tcp->{data} =~ /^GET |^POST |^HEAD |^PUT |^DELETE |^TRACE |^CONNECT /i) {
				my @lines = split("\n", $tcp->{data});
				my $methUri = shift(@lines);
				my @methodData = split(" ", $methUri);

				$ref->{$primaryKey}->{protos}->{l7} = 'http';
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

				$ref->{$primaryKey}->{protos}->{l7} = 'http';
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

		$ref->{$primaryKey}->{protos}->{l4} = "udp";

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
			$ref->{$primaryKey}->{protos}->{l7} = "dns";
                }

		# NTP Traffic
		if (($ref->{$primaryKey}->{udp}->{dstport} == 123 || $ref->{$primaryKey}->{udp}->{srcport} == 123) && $udp->{data} =~ /^([\x13\x1b\x23\xd3\xdb\xe3]|[\x14\x1c$].......?.?.?.?.?.?.?.?.?[\xc6-\xff])/) {
			$ref->{$primaryKey}->{protos}->{l7} = "ntp";
		}

        } elsif ($ipProto eq "icmp") {
        	$icmp = NetPacket::ICMP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l3} = "icmp";

		$ref->{$primaryKey}->{icmp}->{type} = $icmp->{type};
		$ref->{$primaryKey}->{icmp}->{code} = $icmp->{code};

		if ($payload == 1) {
			if ($icmp->{data}) {
				$ref->{$primaryKey}->{icmp}->{data} = getClean($icmp->{data});
			}
		}
		
	} elsif ($ipProto eq "ipv6-icmp") {
		$icmpV6 = NetPacket::ICMPv6->decode(ipv6_strip(eth_strip($packet)));

		$ref->{$primaryKey}->{protos}->{l3} = "ipv6-icmp";

		$ref->{$primaryKey}->{ipv6_icmp}->{type} = $icmpV6->{type};
		$ref->{$primaryKey}->{ipv6_icmp}->{code} = $icmpV6->{code};
		$ref->{$primaryKey}->{ipv6_icmp}->{cksum} = $icmpV6->{cksum};

		if ($payload == 1) {
			if ($icmpV6->{data}) {
				$ref->{$primaryKey}->{ipv6_icmp}->{data} = getClean($icmpV6->{data});
			}
		}

	} elsif ($ipProto eq "igmp") {
        	$igmp = NetPacket::IGMP->decode($ip->{data});

		$ref->{$primaryKey}->{protos}->{l3} = "igmp";

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

	return;	
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
		#$mess =~ s/[^ -~]/\./g;
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
	my $switch;
	my $name;
	my $value;
	my @patterns;
	my $patFiles = '/etc/l7-protocols/protocols/*.pat';
	while (<$patFiles>) {
		$switch = 0;
		open(my $FH, '<', $_) or warn "Can't open '$_': $!\n";
		@patterns = <$FH>;
		close($FH);
		foreach (@patterns) {
			$line = $_;
			chomp($line);
			if ($line =~ /^#|^\n$|^$/) {
				next;
			} elsif ($switch == 0) {
				$name = $line;
				$switch = 1;
			} elsif ($switch == 1) {
				$value = $line;
				$switch = 0;
			}
		}
		$patterns{$name} = $value;
	}

	#if ($l7Enable == 1) {
	#	my $pattern;
	#	foreach (keys(%patterns)) {
	#		$pattern = qr/$patterns{$_}/;
	#		if ($_ =~ /unknown|unset/) {
	#			next;
	#		}
	#		if ($ref->{$primaryKey}->{raw}->{data} =~ /$pattern/) {
	#			$ref->{$primaryKey}->{l7}->{proto} = $_;
	#		}
	#	}
	#}

	return;
}

#####################################
# log the message given 
#####################################
sub logIt {
	$message = shift;
	if ($logging == 1) {
		openlog("$0", "ndelay,pid", "local0");
		syslog("info|local0", $message);
		closelog();
	}
	return;
}

#####################################
# print message to stdout for debug 
#####################################
sub debugOut {
	$message = shift;
	if ($debug == 1) {
		print "$message";
	}
	return;
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
	print "\t$0 -i eth0 -c 10 -j\n";
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
	my $revHost = gethostbyaddr($ipaddr, AF_INET);

	if (defined($revHost)) {
		return($revHost);
	} else {
		return("unknown");
	}
}

#####################################
# Apply index retention policy 
#####################################

sub cleanIndex {
	my $retention = shift;
	my $mtime;
	my $convTime;
	my $hourCount = 0;
	my %times;
	my $hourToSec;

	while ($hourCount <= $retention) {
		if ($hourCount == 0) {
			$hourToSec = 0;
		} else {
			$hourToSec = ($hourCount * 60) * 60;
		}
		$mtime = time() - $hourToSec;
		$convTime = strftime("%Y.%m.%d.%H", localtime($mtime));
		$hourCount++;
		$times{$esPrefix.$convTime} = 1;
	}

	my $indexList = $e->cat->indices(h => ['index']);
	my @indices = split(/\n/, $indexList);

	foreach my $indexRet (@indices) {
		$indexRet =~ s/ $//;
		if ($indexRet =~ /^$esPrefix/) {
			if (exists($times{$indexRet})) {
				$message = "index $indexRet KEEPING\n";
				print "$message";
				logIt($message);
				next;
			} else {
				$message = "index $indexRet too old.. DELETING\n";
				print "$message";
				logIt($message);
				$e->indices->delete(index=>"$indexRet");
			}
		}
	}
	
	return;
}
