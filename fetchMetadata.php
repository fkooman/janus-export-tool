<?php

require_once 'vendor/autoload.php';

use Guzzle\Http\Client;

$config = parse_ini_file(__DIR__ . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "config.ini", TRUE);

$dirName         = isset($config['export']['dir']) ? $config['export']['dir'] : NULL;

// required parameters
if (NULL === $dirName) {
    die("export directory needs to be set in configuration file" . PHP_EOL);
}

// FIXME: create dir if it does not exist!
$metadataDirName = $dirName . DIRECTORY_SEPARATOR . "metadata";

// create the directory if it not set
if (!is_dir($metadataDirName) && FALSE === @mkdir($metadataDirName, 0777, TRUE)) {
    die("unable to create the directory '$metadataDirName'" . PHP_EOL);
}

// remove all metadata files, we will fetch everything again
foreach (glob($metadataDirName . "/*.xml") as $f) {
    unlink($f);
}

$jsonData = file_get_contents($dirName . DIRECTORY_SEPARATOR . "saml20-idp-remote.json");
$idpData = json_decode($jsonData, TRUE);
$jsonData = file_get_contents($dirName . DIRECTORY_SEPARATOR . "saml20-sp-remote.json");
$spData = json_decode($jsonData, TRUE);

$data = $idpData + $spData;

foreach ($data as $metadata) {
    $entityId = $metadata['entityid'];
    if (!isset($metadata['metadata-url'])) {
        continue;
    }
    $metadataUrl = $metadata['metadata-url'];
    try {
        $fileName = $metadataDirName . DIRECTORY_SEPARATOR . md5($metadataUrl) . ".xml";
        // FIXME: we SHOULD also use conditional download, by looking at Last-Modified and/or ETag header
        if (!file_exists($fileName)) {
            $md = fetchMetadata($metadataUrl);
            if (FALSE === @file_put_contents($fileName, $md)) {
                throw new Exception("unable to write metadata to file");
            }
        }
    } catch (Exception $e) {
        //echo $entityId . PHP_EOL;
        //echo "\tWARNING: " . $e->getMessage() . PHP_EOL;
    }
}

function fetchMetadata($metadataUrl)
{
    $client = new Client($metadataUrl, array(
        // set timeout
        'curl.options'   => array(CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 15),
    ));
    $request = $client->get();
    $response = $request->send();
    echo "    Last-Modified: " . $response->getLastModified() . PHP_EOL;
    echo "    Etag         : " . $response->getEtag() . PHP_EOL;

    return $response->getBody();
}
