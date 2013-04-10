<?php
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

ob_start();
require __DIR__ . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . "entityLog.php";
$output = ob_get_clean();
file_put_contents($dirName . DIRECTORY_SEPARATOR . "export.html", $output);
