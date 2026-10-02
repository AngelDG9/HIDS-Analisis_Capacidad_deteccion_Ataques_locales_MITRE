#!/bin/sh
# ATA055 lease_script.sh — registra el LEASE obtenido del servidor señuelo.
# Deliberadamente NO configura la interfaz (solo evidencia): el cliente efimero
# vive en un par veth aislado, asi que no hay riesgo de romper la red.
{
  echo "action=$1 interface=$interface ip=$ip mask=$mask router=$router dns=$dns serverid=$serverid lease=$lease"
} >> /home/angel/lab-attack/ATA055/lease.obtained
exit 0
