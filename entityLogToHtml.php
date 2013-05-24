<?php
date_default_timezone_set("Europe/Amsterdam");

$config = parse_ini_file(__DIR__ . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "config.ini", TRUE);

// export
$dirName        = isset($config['export']['dir']) ? $config['export']['dir'] : NULL;
$janusHost      = isset($config['export']['janusHost']) ? $config['export']['janusHost'] : NULL;

// required parameters
if (NULL === $dirName) {
    die("export directory needs to be set in configuration file" . PHP_EOL);
}
if (NULL === $janusHost) {
    die("export janusHost needs to be set in configuration file" . PHP_EOL);
}

$jsonData = file_get_contents($dirName . DIRECTORY_SEPARATOR . "entityLog.json");
$data = json_decode($jsonData, TRUE);

// sort the entries by state, and then entityId
// the key is the entityId, the state is the attribute 'state';

$prodAcceptedData = array();
$testAcceptedData = array();

foreach ($data as $set => $entries) {
    $prodAccepted = array();
    $testAccepted = array();

    foreach ($entries as $eid => $metadata) {
        if ("prodaccepted" === $metadata['state']) {
            $prodAccepted[$eid] = $metadata;
        }
        if ("testaccepted" === $metadata['state']) {
            $testAccepted[$eid] = $metadata;
        }
    }
    uasort($prodAccepted, 'sortByName');
    $prodAcceptedData[$set] = $prodAccepted;
    uasort($testAccepted, 'sortByName');
    $testAcceptedData[$set] = $testAccepted;
}

function sortByName($a, $b)
{
    if (isset($a['name']) && isset($b['name'])) {
        return strcasecmp($a['name'], $b['name']);
    }

    return 0;
}

ksort($prodAcceptedData);
ksort($testAcceptedData);

$dateTime = date("r");

ob_start();
require __DIR__ . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . "entityLog.php";
$output = ob_get_clean();
file_put_contents($dirName . DIRECTORY_SEPARATOR . "export.html", $output);
