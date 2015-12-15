#!/bin/bash
set -e
./gen_root_ca.sh capass changeit
./gen_node_cert.sh 0 changeit capass && ./gen_node_cert.sh 1 changeit capass &&  ./gen_node_cert.sh 2 changeit capass