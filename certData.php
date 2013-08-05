<?php
# examples:

# get the data for the second certificate of the idp entity matching "ncoi":
# php certData.php ncoi 1
#
# get the expiry date for the idp entity matching "hubrecht":
# php certData.php hubrecht | fold -w64 | openssl base64 -d  | openssl x509 -inform DER -noout -enddate
#
# copy the certificate data for the idp entity matching "hubrecht" to the clipboard (Mac OSX only):
# php certData.php hubrecht | pbcopy

$search = $argc > 1 ? $argv[1] : NULL;
$index = $argc > 2 ? $argv[2] : NULL;

if ($search === NULL) {
    error_log( "usage: php $argv[0] eid [index]" );
    exit(-1);
}

$s = file_get_contents("https://stats.surfconext.nl/sr/parsed-metadata.json", true);
$s=json_decode($s, TRUE);
$idps = $s["saml20-idp-remote"];

$candidates = array();
foreach (array_keys($idps) as $eid) {
    if ( stripos($eid, $search) !== FALSE ) {
        array_push($candidates, $eid);
    }
}
if ( count($candidates) < 1 ) {
    error_log( "no matching idps searching for $search" );
    exit(-1);
}
if ( count($candidates) > 1 ) {
    error_log( "ambiguous search string $search, matching IDPs:" );
    foreach( $candidates as $eid ) error_log($eid);
    exit(-1);
}

$eid = $candidates[0];
error_log( "matching $eid" );

$idp = $idps[$eid];
$certData = $idp["certData"];

if ( count($certData) < 1 ) {
    error_log( "no certificates found for $eid\n" );
    exit(-1);
}

if ( count($certData) > 1 and $index === NULL ) {
    error_log( "multiple certificates for idp $eid, please select an index between 0 and " . (count($certData)-1) );
    exit(-1);
}

if( $index === NULL ) $index = 0;

if ( $index < 0 or $index >= count($certData) ) {
    error_log( "please select an index between 0 and " . (count($certData)-1) );
    exit(-1);
}

$cert = $certData[$index];
echo $cert, "\n";
