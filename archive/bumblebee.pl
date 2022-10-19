#!/usr/bin/perl
# Bumble Bee elastic search index manager
# for elastic search.
# author: woodyk@gmail.com
#

use strict;
use JSON;
use Search::Elasticsearch;
use POSIX;

$ENV{TZ} = 'UTC';

my $e;

# index pattern
# profiler_2016.07.08.01
my $eshost	= "192.168.4.12:9200";
my $esprefix 	= "test_";		# index prefix being rotated
#my $retention	= "72";			# Retention in hours starting at 0
my $retention	= "24";			# Retention in hours starting at 0
my @elNodes;				# elastic search host, and port

push(@elNodes, $eshost);

my $mtime;
my $convTime;
my $hourCount = 0;
my $times;

while ($hourCount <= $retention) {
	my $hourToSec;
	if ($hourCount == 0) {
		$hourToSec = 0;
	} else {
		$hourToSec = ($hourCount * 60) * 60;
	}
	$mtime = time() - $hourToSec;
	$convTime = strftime("%Y.%m.%d.%H", localtime($mtime));
	$hourCount++;
	$times->{$esprefix.$convTime} = 1;
}

$e = Search::Elasticsearch->new( nodes => @elNodes );

my $indexList = $e->cat->indices(h => ['index']);

my @indices = split(/\n/, $indexList);

if ($retention eq "none") {
	print "Index retention is set to \"none\".\n";
	print "Prefix: $esprefix\n";
	print "Elasticsearch host: $eshost\n";
	print "Continue (Y/N)\n";	

	my $input = <STDIN>;
	chomp($input);
	unless ($input eq "Y") {
		print "Canceled index removal. [Exiting]\n";
	}
}

foreach my $indexRet (@indices) {
	$indexRet =~ s/ $//;
	if ($indexRet =~ /^$esprefix/) {
		if ($retention eq "none") {
			print "$indexRet DELETING\n";
			$e->indices->delete(index=>"$indexRet");
			next;
		}  

		if ($times->{$indexRet} == 1) {
			print "$indexRet KEEPING\n";
			next;
		} else {
			print "$indexRet too old.. deleting\n";
			$e->indices->delete(index=>"$indexRet");
		}
	}
	
	
}
