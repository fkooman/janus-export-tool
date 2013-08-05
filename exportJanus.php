<?php

date_default_timezone_set("Europe/Amsterdam");

require_once 'vendor/autoload.php';

require_once 'MetadataParser.php';

use \fkooman\X509\CertParser as CertParser;
use \fkooman\X509\CertParserException as CertParserException;

$config = parse_ini_file(__DIR__ . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "config.ini", TRUE);

// database
$dbDsn          = isset($config['database']['dsn']) ? $config['database']['dsn'] : NULL;
$dbUser         = isset($config['database']['user']) ? $config['database']['user'] : NULL;
$dbPass         = isset($config['database']['pass']) ? $config['database']['pass'] : NULL;
// export
$dirName        = isset($config['export']['dir']) ? $config['export']['dir'] : NULL;
// filter
$requestedState = isset($config['filter']['state']) ? $config['filter']['state'] : NULL;

$requiredIdpAclProdAccepted = isset($config['require:prodaccepted']['idp']) ? $config['require:prodaccepted']['idp'] : NULL;
$requiredSpAclProdAccepted  = isset($config['require:prodaccepted']['sp']) ? $config['require:prodaccepted']['sp'] : NULL;
$requiredIdpAclTestAccepted = isset($config['require:testaccepted']['idp']) ? $config['require:testaccepted']['idp'] : NULL;
$requiredSpAclTestAccepted  = isset($config['require:testaccepted']['sp']) ? $config['require:testaccepted']['sp'] : NULL;

// required parameters
if (NULL === $dbDsn) {
    die("database DSN needs to be set in configuration file" . PHP_EOL);
}
if (NULL === $dirName) {
    die("export directory needs to be set in configuration file" . PHP_EOL);
}

$metadataDirName = $dirName . DIRECTORY_SEPARATOR . "metadata";

$pdo = new PDO($dbDsn, $dbUser, $dbPass);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$data = array();

$sql = <<< EOF
    SELECT
        metadataurl, arp, eid, type, allowedall, entityid, state, revisionid
    FROM
        janus__entity e
    WHERE
        active = "yes" AND revisionid = (SELECT
                MAX(revisionid)
            FROM
                janus__entity
            WHERE
                eid = e.eid)
EOF;

$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

$saml20_idp = array();
$saml20_sp = array();
$allAttributes = array();
$log = array();

// for every entry fetch the metadata
foreach ($result as $r) {
    $metadata = array();

$sql = <<< EOF
    SELECT
        `key`, `value`
    FROM
        janus__metadata
    WHERE
        eid = :eid AND revisionid = :revisionid
EOF;

    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $r['eid']);
    $sth->bindValue(":revisionid", $r['revisionid']);
    $sth->execute();
    $m = $sth->fetchAll(PDO::FETCH_ASSOC);
    foreach ($m as $kv) {
        $metadata[$kv['key']] = $kv['value'];
    }

    // turn all entries with a ":" into proper arrays
    arrayizeMetadata($metadata);

    // add ARP if SP
    if ("saml20-sp" === $r['type']) {
        $sql = "SELECT attributes FROM janus__arp WHERE aid = :aid";
        $sth = $pdo->prepare($sql);
        $sth->bindValue(":aid", $r['arp']);
        $sth->execute();
        $arpResult = $sth->fetch(PDO::FETCH_ASSOC);
        if (NULL !== $arpResult['attributes']) {
            $attributes = array_keys(unserialize($arpResult['attributes']));
            if (0 === count($attributes)) {
                // no attributes, good
                $metadata['attributes'] = FALSE;
            } else {
                // some attributes, also good
                $metadata['attributes'] = $attributes;
                $allAttributes = array_unique(array_merge($allAttributes, $attributes));
            }
        } else {
            // no ARP, so *all* possible attributes, not good
            $metadata['attributes'] = array();
        }
    }

    // add consent disabling if IdP
    if ("saml20-idp" === $r['type']) {
        $sql = "SELECT remoteentityid FROM janus__disableConsent WHERE eid = :eid AND revisionid = :revisionid";
        $sth = $pdo->prepare($sql);
        $sth->bindValue(":eid", $r['eid']);
        $sth->bindValue(":revisionid", $r['revisionid']);
        $sth->execute();
        $disableConsentResult = $sth->fetchAll(PDO::FETCH_COLUMN);
        if (FALSE !== $disableConsentResult && 0 !== count($disableConsentResult)) {
            $metadata['consent.disable'] = $disableConsentResult;
        }
    }

$sql = <<< EOF
    SELECT
        e.entityid
    FROM
        `janus__entity` e,
        `janus__allowedEntity` a
    WHERE
        a.eid = :eid AND a.revisionid = :revisionid
            AND e.eid = a.remoteeid
            AND e.revisionid = (SELECT
                MAX(revisionid)
            FROM
                `janus__entity`
            WHERE
                eid = a.remoteeid)
EOF;

    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $r['eid']);
    $sth->bindValue(":revisionid", $r['revisionid']);
    $sth->execute();
    $a = $sth->fetchAll(PDO::FETCH_COLUMN);

    $metadata['allowAll'] = "yes" === $r['allowedall'];

    $metadata['entityid'] = $r['entityid'];
    $metadata['eid'] = $r['eid'];
    $metadata['metadata-set'] = $r['type'] . "-remote";
    $metadata['state'] = $r['state'];
    $metadata['metadata-url'] = $r['metadataurl'];

    $log[$metadata['metadata-set']][$metadata['entityid']]['messages'] = array();
    $log[$metadata['metadata-set']][$metadata['entityid']]['state'] = $metadata['state'];
    $log[$metadata['metadata-set']][$metadata['entityid']]['eid'] = $metadata['eid'];
    if (isset($metadata['name']['en'])) {
        $log[$metadata['metadata-set']][$metadata['entityid']]['name'] = $metadata['name']['en'];
    }

    if ("saml20-sp-remote" === $metadata['metadata-set'] && is_array($metadata['attributes']) && 0 === count($metadata['attributes'])) {
        // no ARP
        _l($metadata, "WARNING", "no ARP set");
    }

    if ($metadata['metadata-set'] === "saml20-sp-remote") {
        $metadata['IDPList'] = $a;
        $saml20_sp[$r['entityid']] = $metadata;
    } elseif ($metadata['metadata-set'] === "saml20-idp-remote") {
        $metadata['SPList'] = $a;
        $saml20_idp[$r['entityid']] = $metadata;
    } else {
        throw new Exception("unsupported entity type");
    }
}

echo count($saml20_idp) . " IdPs" . PHP_EOL;
echo count($saml20_sp) . " SPs" . PHP_EOL;

resolveAcl($saml20_idp, $saml20_sp);

convertToUIInfo($saml20_idp);
convertToUIInfo($saml20_sp);

validateContacts($saml20_idp);
validateContacts($saml20_sp);

validateEndpoints($saml20_idp);
validateEndpoints($saml20_sp);

validateMetadataURL($saml20_idp);
validateMetadataURL($saml20_sp);

checkName($saml20_idp);
checkName($saml20_sp);

verifyOrganization($saml20_idp);
verifyOrganization($saml20_sp);

verifyCertificates($saml20_idp);

verifyOAuth($saml20_sp);

removeSecrets($saml20_sp);

updateRedirectSign($saml20_idp);
updateRedirectSign($saml20_sp);

updateSpConsent($saml20_sp);

verifyRequiredConnections($saml20_idp, $saml20_sp);

if (NULL !== $requestedState) {
    filterState($saml20_idp, $requestedState);
    filterState($saml20_sp, $requestedState);
}

if (FALSE === @file_put_contents($dirName . DIRECTORY_SEPARATOR . "saml20-idp-remote.json", json_encode(array_values($saml20_idp)))) {
    throw new Exception("unable to write 'saml20-idp-remote.json'");
}
if (FALSE === @file_put_contents($dirName . DIRECTORY_SEPARATOR . "saml20-sp-remote.json", json_encode(array_values($saml20_sp)))) {
    throw new Exception("unable to write 'saml20-sp-remote.json'");
}

sort($allAttributes);
if (FALSE === @file_put_contents($dirName . DIRECTORY_SEPARATOR . "allAttributes.json", json_encode(array_values($allAttributes)))) {
    throw new Exception("unable to write 'allAttributes.json'");
}

cleanLog();
if (FALSE === @file_put_contents($dirName . DIRECTORY_SEPARATOR . "entityLog.json", json_encode($log))) {
    throw new Exception("unable to write 'entityLog.json'");
}

function arrayizeMetadata(&$metadata)
{
    foreach ($metadata as $k => $v) {
        // if k contain as colon there may be multiple values underneath
        if (empty($v)) {
            unset($metadata[$k]);
        } else {
            if (FALSE !== strpos($k, ":")) {
                $e = explode(":", $k);
                if (2 === count($e)) {
                    // only simple case for now
                    $metadata[$e[0]][$e[1]] = $v;
                    unset($metadata[$k]);
                } elseif (3 === count($e)) {
                    $metadata[$e[0]][$e[1]][$e[2]] = $v;
                    unset($metadata[$k]);
                } elseif (4 === count($e)) {
                    $metadata[$e[0]][$e[1]][$e[2]][$e[4]] = $v;
                    unset($metadata[$k]);
                } else {
                    throw new Exception("unsupported array depth in metadata");
                }
            }
        }
    }
}

function resolveAcl(&$idp, &$sp)
{
    // log "wrong" allowAll usage
    foreach ($sp as $speid => $spmetadata) {
        if (!$spmetadata['allowAll']) {
            _l($spmetadata, 'WARNING', 'allowAll not set');
        }
    }
    foreach ($idp as $idpeid => $idpmetadata) {
        if ($idpmetadata['allowAll']) {
            _l($idpmetadata, 'WARNING', 'allowAll set');
        }
    }

    // loop through all SPs
    // is allow all set?
    // YES:
    //      loop through IdPs with same state
    //      Idp has allow all set?
    //      YES: add IdP to SP ACL
    //      Idp has SP in ACL?
    //      YES: add IdP to SP ACL
    // NO:
    //      loop through IdPs mentioned (with same state)
    //      IdP has allow all set?
    //      YES: add IdP to SP ACL
    //      IdP has SP in ACL?
    //      YES: add IdP to SP ACL

    // loop through all SPs
    foreach ($sp as $speid => $spmetadata) {
        $sp[$speid]['SPACL'] = array();

        // SP allowAll?
        if ($spmetadata['allowAll']) {
            // SP allowAll
            // loop through all IdPs
            foreach ($idp as $idpeid => $idpmetadata) {
                // same state?
                if ($idpmetadata['state'] === $spmetadata['state']) {
                    // same state
                    // IdP allowAll?
                    if ($idpmetadata['allowAll']) {
                        // IdP allowAll
                        array_push($sp[$speid]['SPACL'], $idpeid);
                    } else {
                        // !IdP allowAll
                        // IdP has SP in ACL?
                        if (in_array($speid, $idpmetadata['SPList'])) {
                            // YES
                            array_push($sp[$speid]['SPACL'], $idpeid);
                        }
                    }
                }
            }
        } else {
            // !SP allowAll
            // loop through all mentioned IdPs
            foreach ($spmetadata['IDPList'] as $idpeid) {
                // FIXME: may not exist!
                if (isset($idp[$idpeid])) {
                    $idpmetadata = $idp[$idpeid];
                    // same state?
                    if ($idpmetadata['state'] === $spmetadata['state']) {
                        // same state
                        // IdP allowAll?
                        if ($idpmetadata['allowAll']) {
                            // IdP allowAll
                            array_push($sp[$speid]['SPACL'], $idpeid);
                        } else {
                            // !IdP allowAll
                            // IdP has SP in ACL?
                            if (in_array($speid, $idpmetadata['SPList'])) {
                                // YES
                                array_push($sp[$speid]['SPACL'], $idpeid);
                            }
                        }
                    }
                }
            }
        }
        $sp[$speid]['IDPList'] = $sp[$speid]['SPACL'];
        unset($sp[$speid]['SPACL']);
    }
    // remove SPList from IdP entries
    foreach ($idp as $idpeid => $idpmetadata) {
        unset($idp[$idpeid]['SPList']);
    }
}

function validateContacts(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (array_key_exists("contacts", $metadata)) {
            foreach ($metadata['contacts'] as $k => $v) {
                $errorMessage = array();
                $filteredContact = filterContact($v, $errorMessage);
                if (FALSE !== $filteredContact) {
                    $entities[$eid]["contacts"][$k] = $filteredContact;
                } else {
                    _l($metadata, "WARNING", "invalid contact data " . $k . " (" . implode(", ", $errorMessage) . ")");
                    unset($entities[$eid]["contacts"][$k]);
                }
            }
            $entities[$eid]['contacts'] = array_values($entities[$eid]['contacts']);
        }
    }
}

function validateEndpoints(&$entities)
{
    $endpointTypes = array("SingleLogoutService", "SingleSignOnService", "AssertionConsumerService");

    foreach ($entities as $eid => $metadata) {
        foreach ($endpointTypes as $type) {
            if (array_key_exists($type, $metadata)) {
                foreach ($metadata[$type] as $k => $v) {
                    $errorMessage = array();
                    $filteredEndpoint = filterEndpoint($v, $errorMessage);
                    if (FALSE !== $filteredEndpoint) {
                        $entities[$eid][$type][$k] = $filteredEndpoint;
                    } else {
                        _l($metadata, "WARNING", "invalid endpoint configuration " . $k . " (" . implode(", ", $errorMessage) . ")");
                        unset($entities[$eid][$type][$k]);
                    }
                }
                $entities[$eid][$type] = array_values($entities[$eid][$type]);
                if (0 === count($entities[$eid][$type])) {
                    unset($entities[$eid][$type]);
                }
            }
        }
    }
}

function convertToUIInfo(&$entities)
{
    // some keys belong in UIInfo (under a different name)
    foreach ($entities as $eid => $metadata) {
        $uiInfo = array();
        $discoHints = array();

        if (array_key_exists("displayName", $metadata)) {
            $uiInfo['DisplayName'] = $metadata['displayName'];
            unset($entities[$eid]['displayName']);
        }
        if (array_key_exists("keywords", $metadata)) {
            foreach ($metadata['keywords'] as $language => $keywords) {
                $filteredKeywords = filterKeywords($keywords);
                if (0 !== count($filteredKeywords)) {
                    $uiInfo['Keywords'][$language] = $filteredKeywords;
                }
            }
            unset($entities[$eid]['keywords']);
        }
        if (array_key_exists("geoLocation", $metadata)) {
            $geo = validateGeo($metadata['geoLocation']);
            if (FALSE !== count($geo)) {
                $discoHints['GeolocationHint'] = array($geo);
            } else {
                _l($metadata, "WARNING", "invalid GeolocationHint");
            }
            unset($entities[$eid]['geoLocation']);
        }
        if (array_key_exists("logo", $metadata)) {
            $errorMessage = array();
            $logo = validateLogo($metadata["logo"][0], $errorMessage);
            if (FALSE !== $logo) {
                $uiInfo['Logo'] = array($logo);
            } else {
                _l($metadata, "WARNING", "invalid Logo configuration (" . implode(", ", $errorMessage) . ")");
            }
            unset($entities[$eid]['logo']);
        }
        if (0 !== count($uiInfo)) {
            $entities[$eid]['UIInfo'] = $uiInfo;
        }
        if (0 !== count($discoHints)) {
            $entities[$eid]['DiscoHints'] = $discoHints;
        }

    }
}

function validateLogo(array $logo, array &$errorMessage)
{
    if (!array_key_exists("url", $logo)) {
        array_push($errorMessage, "missing URL");
    } else {
        if (FALSE === filter_var($logo['url'], FILTER_VALIDATE_URL, FILTER_FLAG_PATH_REQUIRED)) {
            array_push($errorMessage, "invalid URL");
        }
    }
    if (!array_key_exists("width", $logo) || !is_numeric($logo['width'])) {
        array_push($errorMessage, "missing or invalid width");
    }
    if (!array_key_exists("height", $logo) || !is_numeric($logo['height'])) {
        array_push($errorMessage, "missing or invalid height");
    }

    if (0 !== count($errorMessage)) {
        return FALSE;
    }

//     $size = @getimagesize($logo['url']);
//     if (FALSE === $size || !is_array($size) || 2 > count($size)) {
//         array_push($errorMessage, "unable to retrieve image size from URL");
//     }
//     $width = $size[0];
//     $height = $size[1];
//
//     if ((int) $logo['width'] !== $width) {
//         array_push($errorMessage, "invalid width (" . $logo['width'] . "), actual width is " . $width);
//     }
//     if ((int) $logo['height'] !== $height) {
//         array_push($errorMessage, "invalid height (" . $logo['height'] . "), actual height is " . $height);
//     }
//
//     if (0 !== count($errorMessage)) {
//         return FALSE;
//     }

    $l = array ("url" => $logo['url'], "width" => (int) $logo['width'], "height" => (int) $logo['height']);
    if (array_key_exists("lang", $logo) && !empty($logo['lang'])) {
        $l['lang'] = $logo['lang'];
    }

    return $l;
}

function filterKeywords($keywords)
{
    $keywordsArray = explode(" ", $keywords);
    foreach ($keywordsArray as $k) {
        $keywordsArray = array_filter($keywordsArray, function($v) {
            if (empty($v)) {
                return FALSE;
            }
            if (strpos($v, "+") !== FALSE) {
                return FALSE;
            }
            if (htmlentities($v) !== $v) {
                return FALSE;
            }

            return TRUE;
        });
    }
    sort($keywordsArray);

    return array_values(array_unique($keywordsArray));
}

function filterContact(array $contact, array &$errorMessage)
{
    $validContactTypes = array ("technical", "administrative", "support", "billing", "other");
    if (!array_key_exists("contactType", $contact)) {
        array_push($errorMessage, "missing contactType");
    } else {
        if (!in_array($contact['contactType'], $validContactTypes)) {
            array_push($errorMessage, "unsupported contactType");
        }
    }
    if (array_key_exists("emailAddress", $contact)) {
        if (FALSE === filter_var($contact['emailAddress'], FILTER_VALIDATE_EMAIL)) {
            array_push($errorMessage, "invalid emailAddress");
        }
    }

    if (0 !== count($errorMessage)) {
        return FALSE;
    }

    $c = array("contactType" => $contact['contactType']);

    if (array_key_exists("emailAddress", $contact) && !empty($contact['emailAddress'])) {
        $c['emailAddress'] = $contact['emailAddress'];
    }
    if (array_key_exists("givenName", $contact) && !empty($contact['givenName'])) {
        $c['givenName'] = $contact['givenName'];
    }
    if (array_key_exists("surName", $contact) && !empty($contact['surName'])) {
        $c['surName'] = $contact['surName'];
    }
    if (array_key_exists("telephoneNumber", $contact) && !empty($contact['telephoneNumber'])) {
        $c['telephoneNumber'] = $contact['telephoneNumber'];
    }

    return $c;
}

function filterEndpoint(array $ep, array &$errorMessage)
{
    // an ACS, SSO or SLO should have a "Binding" and a "Location" field
    if (!array_key_exists("Location", $ep)) {
        array_push($errorMessage, "Location field missing");
    } else {
        if (FALSE === filter_var($ep['Location'], FILTER_VALIDATE_URL, FILTER_FLAG_PATH_REQUIRED)) {
            array_push($errorMessage, "invalid URL");
        }
        if (0 === strpos($ep['Location'], "http://")) {
            array_push($errorMessage, "non SSL endpoint URL specified");
        }
    }

    if (!array_key_exists("Binding", $ep)) {
        array_push($errorMessage, "Binding field missing");
    }

    if (0 !== count($errorMessage)) {
        return FALSE;
    }

    $validatedEndpoint = array("Location" => $ep['Location'], "Binding" => $ep['Binding']);

    if (array_key_exists("Index", $ep) && !empty($ep['Index']) && is_numeric($ep['Index'])) {
        $validatedEndpoint['Index'] = (int) $ep['Index'];
    }
    if (array_key_exists("index", $ep) && !empty($ep['index']) && is_numeric($ep['index'])) {
        $validatedEndpoint['index'] = (int) $ep['index'];
    }

    return $validatedEndpoint;
}

function removeSecrets(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (isset($metadata['coin']['oauth']['secret'])) {
            $entities[$eid]['coin']['oauth']['secret'] = 'REPLACED_BY_EXPORT_SCRIPT';
        }
        if (isset($metadata['coin']['oauth']['consumer_secret'])) {
            $entities[$eid]['coin']['oauth']['consumer_secret'] = 'REPLACED_BY_EXPORT_SCRIPT';
        }
        if (isset($metadata['coin']['provision_password'])) {
            $entities[$eid]['coin']['provision_password'] = 'REPLACED_BY_EXPORT_SCRIPT';
        }
    }
}

function filterState(&$entities, $requestedState)
{
    global $log;
    foreach ($entities as $eid => $metadata) {
        if ($requestedState !== $metadata['state']) {
            unset($entities[$eid]);
            unset($log[$metadata['metadata-set']][$eid]);
        }
    }
}

function checkName(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (array_key_exists("name", $metadata) && is_array($metadata['name']) && array_key_exists("en", $metadata["name"]) && !empty($metadata["name"]["en"])) {
            // all is fine
            continue;
        } else {
            _l($metadata, "WARNING", "no name:en set");
        }
    }
}

function validateGeo($geoHints)
{
    if (!empty($geoHints)) {
        $e = explode(",", $geoHints);
        if (2 !== count($e) && 3 !== count($e)) {
            return FALSE;
        }
        if (2 === count($e)) {
            list($lat, $lon) = $e;
            $lat = trim($lat);
            $lon = trim($lon);

            return "geo:$lat,$lon";
        }
        if (3 === count($e)) {
            list($lat, $lon, $alt) = $e;
            $lat = trim($lat);
            $lon = trim($lon);
            $alt = trim($alt);

            return "geo:$lat,$lon,$alt";
        }
    }
}

function updateRedirectSign(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (isset($metadata['redirect.sign'])) {
            if ("saml20-idp-remote" === $metadata['metadata-set']) {
                // IdP
                $entities[$eid]['redirect.sign'] = $metadata['redirect.sign'] ? TRUE : FALSE;
            } else {
                // SP
                $entities[$eid]['validate.authnrequest'] = $metadata['redirect.sign'] ? TRUE : FALSE;
                unset($entities[$eid]['redirect.sign']);
            }
        }
    }
}

function updateSpConsent(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (isset($metadata['coin']['no_consent_required'])) {
            $entities[$eid]['consent.disable'] = $metadata['coin']['no_consent_required'] == 1 ? TRUE : FALSE;
            unset($entities[$eid]['coin']['no_consent_required']);
        }
    }
}

function validateMetadataUrl(&$entities)
{
    global $metadataDirName;

    foreach ($entities as $eid => $metadata) {
        if (NULL === $metadata['metadata-url']) {
            _l($metadata, "WARNING", "no metadata URL specified");
            unset($entities[$eid]['metadata-url']);
        } else {
            $mdu = trim($metadata['metadata-url']);
            if (FALSE === filter_var($mdu, FILTER_VALIDATE_URL)) {
                _l($metadata, "WARNING", sprintf("invalid metadata URL specified '%s'", $mdu));
                unset($entities[$eid]['metadata-url']);
            } else {
                if (0 === strpos($mdu, "http://")) {
                    _l($metadata, "WARNING", sprintf("non SSL metadata URL specified '%s'", $mdu));
                }
                $entities[$eid]['metadata-url'] = $mdu;

                // here we check if the fetching of the metadata succeeded
                $metadataFile = @file_get_contents($metadataDirName . DIRECTORY_SEPARATOR . md5($mdu) . ".xml");
                // FIXME: do not load the file twice!
                if (FALSE === $metadataFile) {
                    _l($metadata, "WARNING", sprintf("unable to fetch metadata from metadata URL '%s'", $mdu));
                    continue;
                }
                compareMetadata($metadata, $metadataDirName . DIRECTORY_SEPARATOR . md5($mdu) . ".xml");
            }
        }
    }
}

function verifyOrganization(&$entities)
{
    // if any of OrganizationDisplayName, OrganizationName or OrganizationURL is
    // set they MUST all be set, for now we require all to be set to not give warnings

    foreach ($entities as $eid => $metadata) {
        if (!isset($metadata['OrganizationDisplayName']['en']) && !isset($metadata['OrganizationDisplayName']['nl'])) {
            _l($metadata, "WARNING", "missing OrganizationDisplayName");
        }
        if (!isset($metadata['OrganizationName']['en']) && !isset($metadata['OrganizationName']['nl'])) {
            _l($metadata, "WARNING", "missing OrganizationName");
        }
        if (!isset($metadata['OrganizationURL']['en']) && !isset($metadata['OrganizationURL']['nl'])) {
            _l($metadata, "WARNING", "missing OrganizationURL");
        }
    }
}

function verifyCertificates(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if ( (!array_key_exists('certData', $metadata) || empty($metadata['certData'])) && (!array_key_exists('certData2', $metadata) || empty($metadata['certData2']))) {
            _l($metadata, "ERROR", "no certificate configured for this IdP");
        }
        verifyCertificate($metadata, 'certData');
        verifyCertificate($metadata, 'certData2');
    }
}

function verifyCertificate($metadata, $key)
{
    // we only check expiry for ADFS, not for other IdPs
    if (FALSE !== strpos($metadata['entityid'], "adfs/services/trust")) {
        if (isset($metadata[$key]) && !empty($metadata[$key])) {
            // available
            try {
                $c = new CertParser($metadata[$key]);
                $expiresAt = $c->getNotValidAfter();
                if (time() > $expiresAt) {
                    _l($metadata, "ERROR", sprintf("certificate in '%s' expired at %s", $key, date("r", $expiresAt)));
                } elseif (time() + 60*60*24*14 > $expiresAt) {
                    _l($metadata, "INFO", sprintf("certificate in '%s' is about to expire at %s", $key, date("r", $expiresAt)));
                }
            } catch (CertParserException $e) {
                _l($metadata, "WARNING", sprintf("unable to parse certificate in '%s': %s", $key, $e->getMessage()));
            }
        }
    }
}

function verifyOAuth(&$entities)
{
    foreach ($entities as $eid => $metadata) {

        if (isset($metadata['coin']['oauth']) && !isset($metadata['coin']['gadgetbaseurl'])) {
            _l($metadata, "WARNING", "OAuth: some parameters specified, no client_id (gadgetbaseurl)");
        }

        if (!isset($metadata['coin']['oauth']) && isset($metadata['coin']['gadgetbaseurl'])) {
            _l($metadata, "WARNING", "OAuth: client_id (gadgetbaseurl) specified, but no other parameters");
        }

        if (isset($metadata['coin']['oauth'])) {
            // some OAuth config is available
            if (isset($metadata['coin']['oauth']['two_legged_allowed'])) {
                _l($metadata, "WARNING", "OAuth: two legged OAuth allowed");
            }
            if (!isset($metadata['coin']['oauth']['callback_url'])) {
                _l($metadata, "WARNING", "OAuth: missing redirect_uri (callback_url)");
            }
            if (!isset($metadata['coin']['gadgetbaseurl'])) {
                _l($metadata, "WARNING", "OAuth: missing client_id (gadgetbaseurl)");
            } else {
                // validate client_id
                $result = preg_match('/^(?:[\x20-\x7E])*$/', $metadata['coin']['gadgetbaseurl']);
                if (1 !== $result || FALSE !== strpos($metadata['coin']['gadgetbaseurl'], ":")) {
                    _l($metadata, "WARNING", "OAuth: client_id (gadgetbaseurl) contains invalid characters");
                }
            }
        }
    }
}

function compareMetadata(array $metadata, $metadataFile)
{
    $entityId = $metadata['entityid'];
    try {
        if ("saml20-idp-remote" === $metadata['metadata-set']) {
            $idpMetadata = MetadataParser::idp($metadataFile, $entityId);

            $janusCert = array();
            foreach (array("certData", "certData2") as $c) {
                if (isset($metadata[$c]) && !empty($metadata[$c])) {
                    $cp = new CertParser($metadata[$c]);
                    array_push($janusCert, $cp->toBase64());
                }
            }

            foreach ($idpMetadata['certData'] as $c) {
                if (!in_array($c, $janusCert)) {
                    $cp = new CertParser($c);
                    _l($metadata, "ERROR", sprintf("METADATA: certificate in metadata missing from configuration [%s, Valid from: %s, Valid to: %s]", $cp->getName(), date("r", $cp->getNotValidBefore()), date("r", $cp->getNotValidAfter())));
                }
            }
        } else {
            $spMetadata = MetadataParser::sp($metadataFile, $entityId);
        }
    } catch (MetadataParserException $e) {
        _l($metadata, "WARNING", "METADATA: " . $e->getMessage());
    }
}

function verifyRequiredConnections(&$idp, &$sp)
{
    global $requiredIdpAclProdAccepted;
    global $requiredSpAclProdAccepted;
    global $requiredIdpAclTestAccepted;
    global $requiredSpAclTestAccepted;

    foreach ($sp as $eid => $metadata) {
        $ri = "prodaccepted" === $metadata['state'] ? $requiredIdpAclProdAccepted : $requiredIdpAclTestAccepted;
        if (NULL !== $ri && 0 !== count($ri)) {
            foreach ($ri as $i) {
                if (!in_array($i, $metadata['IDPList'])) {
                    _l($metadata, "WARNING", "required IdP " . $i . " not in ACL");
                }
            }
        }
    }

    foreach ($idp as $eid => $metadata) {
        $rs = "prodaccepted" === $metadata['state'] ? $requiredSpAclProdAccepted : $requiredSpAclTestAccepted;
        if (NULL !== $rs && 0 !== count($rs)) {
            foreach ($rs as $s) {
                if (!in_array($metadata['entityid'], $sp[$s]['IDPList'])) {
                    _l($metadata, "WARNING", "required SP " . $s . " not in ACL");
                }
            }
        }
    }
}

function _l($metadata, $level, $message)
{
    global $log;
    array_push($log[$metadata['metadata-set']][$metadata['entityid']]['messages'], array("level" => $level, "message" => $message));
}

// remove entries that do not have a log message
function cleanLog()
{
    global $log;
    foreach ($log as $set => $entities) {
        foreach ($entities as $k => $v) {
            if (0 === count($v['messages'])) {
                unset($log[$set][$k]);
            }
        }
    }
}
