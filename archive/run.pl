#!/usr/bin/perl
#
# run.pl -- Wadih Khairallah <wadih@prolexic.com>

use Parallel::ForkManager;
use strict;

my %children;
my $MAX_PROCESSES = 1;
my $TMP_DIR = "/tmp";

my $pm = new Parallel::ForkManager($MAX_PROCESSES, $TMP_DIR);

$pm->run_on_finish(
	sub { my ($pid, $exit_code, $ident) = @_;
		print "** $ident just got out of the pool ".
		"with PID $pid and exit code: $exit_code\n";
	}
);

$pm->run_on_start(
	sub { my ($pid, $ident)=@_;
		print "$ident started, pid: $pid\n";
		sleep 20;
	}
);

sub start_child {
	my $child = $pm->start and next;
	`./optimus.pl`;
	print "Finished $child\n";
	$pm->finish;
}

while ( 1 ) {
	start_child();
	sleep 20;
}
