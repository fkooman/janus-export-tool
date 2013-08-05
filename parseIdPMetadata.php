<?php
require_once 'vendor/autoload.php';
require_once 'MetadataParser.php';

if (3 > $argc) {
    die("Syntax: <metadata URL> <entity ID>" . PHP_EOL);
}

var_export(MetadataParser::idp($argv[1], $argv[2]));
