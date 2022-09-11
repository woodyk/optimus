#!/usr/bin/perl

use Mojolicious::Lite;


# /scan?ip=<ip_address>
get '/scan' => sub {
	my $c	= shift;
	my $ip	= $c->param('ip');
	if ($ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
		$c->render(text => "<b>Scanning IP $ip.</b>");
	} else {
		$c->render(text => "Error: ip not specified.");
	}
};

get '/trace' => sub {
	my $c	= shift;
	my $ip	= $c->param('ip');
	if ($ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
                $c->render(text => "<b>Scanning IP $ip.</b>");
        } else {
                $c->render(text => "Error: ip not specified.");
        }
};

app->start('daemon', '-l', 'https://*:8333');
