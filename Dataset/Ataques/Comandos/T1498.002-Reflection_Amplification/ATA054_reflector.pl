#!/usr/bin/perl
# ATA054_reflector.pl — reflector UDP local (T1498.002), acotado.
# Uso: reflector.pl <bind_ip> <port> <resp_bytes> <max_resp> <timeout_ms>
# Responde a CADA peticion con <resp_bytes> bytes hacia la DIRECCION DE ORIGEN
# (la fuente falsificada por el spoofer) -> reflexion.
use strict;
use warnings;
use Socket;

my ($bind, $port, $resp, $maxresp, $timeout_ms) = @ARGV;
$resp       //= 4096;
$maxresp    //= 25;
$timeout_ms //= 12000;

# cotas duras del reflector
$resp = 8192 if $resp > 8192;
$maxresp = 40 if $maxresp > 40;
$timeout_ms = 15000 if $timeout_ms > 15000;

socket(my $s, AF_INET, SOCK_DGRAM, 0) or die "socket: $!";
setsockopt($s, SOL_SOCKET, SO_REUSEADDR, pack("i", 1)) or die "reuseaddr: $!";
bind($s, sockaddr_in($port, inet_aton($bind))) or die "bind $bind:$port: $!";

my $payload = "R" x $resp;
my $hasta   = time() + int($timeout_ms / 1000) + 1;
my $n = 0;
my $rin = "";
vec($rin, fileno($s), 1) = 1;

while ($n < $maxresp && time() < $hasta) {
    my $sel = select(my $rout = $rin, undef, undef, 1);
    next unless $sel;
    my $peer = recv($s, my $buf, 2048, 0);
    next unless defined $peer;
    send($s, $payload, 0, $peer) or next;    # respuesta al origen (spoofeado)
    $n++;
}

print "reflector: respuestas=$n bytes_amplificados=", $n * $resp, " resp_bytes=$resp\n";
