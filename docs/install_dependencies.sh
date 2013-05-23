#!/bin/sh

rm -rf extlib
mkdir -p extlib

(
cd extlib
git clone https://github.com/fkooman/php-cert-parser.git
)

