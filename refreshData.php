<?php
system("/usr/bin/php " . __DIR__ . DIRECTORY_SEPARATOR . "exportJanus.php");
system("/usr/bin/php " . __DIR__ . DIRECTORY_SEPARATOR . "entityLogToHtml.php");
