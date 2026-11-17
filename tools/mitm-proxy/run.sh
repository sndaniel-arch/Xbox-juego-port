#!/bin/bash
# Start the local MITM proxy (detached). Log: mitm.log in this dir.
# (Ronda 5, auditor F — R5-F12.) Sin set -e ni comprobacion de python3, un
# python3 ausente dejaba el "MITM started" impreso igual y el pid era de un
# nohup ya muerto.
set -euo pipefail
command -v python3 >/dev/null || { echo "python3 no encontrado"; exit 1; }
cd "$(dirname "$0")"
nohup python3 mitm.py > mitm.log 2>&1 &
MITM_PID=$!
# (Ronda 6, auditor F — R6-F12.) set -e no cubre los trabajos en segundo
# plano: si mitm.py muere al arrancar (puerto en uso, error de import), el
# script imprimia "MITM started pid ..." igual y salia 0. Esperar un momento
# y comprobar que el proceso sigue vivo.
sleep 2
kill -0 "$MITM_PID" 2>/dev/null || { echo "MITM no arranco (ver mitm.log)"; exit 1; }
echo "MITM started pid $MITM_PID"
