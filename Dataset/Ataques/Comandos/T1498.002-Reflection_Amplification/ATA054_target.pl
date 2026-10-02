#!/usr/bin/perl
# ATA054_target.pl — escucha en la IP/port falsificados y cuenta lo amplificado.
# Uso: target.pl <bind_ip> <port> <max_pkts> <timeout_ms>
# Salida: "target: paquetes=<n> bytes=<b>" (la victima recibe la amplificacion).
use strict;
use warnings;
use Socket;

my ($bind, $port, $maxpkts, $timeout_ms) = @ARGV;
$maxpkts    //= 25;
$timeout_ms //= 15000;

socket(my $s, AF_INET, SOCK_DGRAM, 0) or die "socket: $!";
setsockopt($s, SOL_SOCKET, SO_REUSEADDR, pack("i", 1)) or die "reuseaddr: $!";
bind($s, sockaddr_in($port, inet_aton($bind))) or die "bind $bind:$port: $!";

my $hasta = time() + int($timeout_ms / 1000) + 1;
my ($pkts, $bytes) = (0, 0);
my $rin = "";
vec($rin, fileno($s), 1) = 1;

while ($pkts < $maxpkts && time() < $hasta) {
    my $sel = select(my $rout = $rin, undef, undef, 1);
    next unless $sel;
    my $peer = recv($s, my $buf, 65535, 0);
    next unless defined $peer;
    $pkts++;
    $bytes += length($buf);
}

print "target: paquetes=$pkts bytes=$bytes\n";
