use JSON;

$json = JSON->new();

$config->{ip6} 		= 0;
$config->{l2}  		= 0;
$config->{l7} 		= 0;
#$config->{quiet}
#$config->{dbug}     
$config->{verbose} 	= 0;
$config->{redis}	= 0;
$config->{tags}		= 0;
$config->{geoip}	= 0;
$config->{output}->{file}	= '<file/path>'; #file path to enable 0 for no file output
$config->{output}->{redis}->{connect}	= '</path/to/socket||server:port>';
$config->{output}->{elastic}->{connect}	= '<http://elastic:9200>';
$config->{output}->{elastic}->{prefix}	= '<index_name_prefix_>';
$config->{input}->{interface} = '<interface name>';
$config->{input}->{pcap} = 'pcap file name';
$config->{payload}->{size} = '<bits>'; # Number ob bits into the payload to record.
$config->{payload}->{offset} = '0';
$config->{bpf}		= "";
$config->{sample}	= '<number of packets to sample>';
$config->{maxPerDest}	= "1000";
$config->{input}->{netflow}	= 0;

$out = $json->encode( $config );

print "$out\n";
