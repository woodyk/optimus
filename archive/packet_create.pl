#!/usr/bin/perl

use strict;
use Net::RawIP;

$n = Net::RawIP->new({
                        ip  => {
                                saddr => 'my.target.lan',
                                daddr => 'my.target.lan',
                               },
                       });
                        tcp => {
                                source => 139,
                                dest   => 139,
                                psh    => 1,
                                syn    => 1,
                               },
                       });
  $n->send;
  $n->ethnew("eth0");
  $n->ethset(source => 'my.target.lan', dest =>'my.target.lan');    
  $n->ethsend;
  $p = $n->pcapinit("eth0", "dst port 21", 1500, 30);
  $f = dump_open($p, "/my/home/log");
  loop($p, 10, \&dump, $f);
