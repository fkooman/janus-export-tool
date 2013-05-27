<?php

use \fkooman\X509\CertParser;

class MetadataParser
{
    public static function idp($file, $entityId)
    {
        $e = @simplexml_load_file($file);
        if (FALSE === $e) {
            throw new MetadataParserException("unable to read metadata file");
        }

        $md = array(
            "SingleSignOnService" => array(),
            "certData" => array()
        );

        $e->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        $result = $e->xpath('//md:EntityDescriptor[@entityID="' . $entityId . '"]/md:IDPSSODescriptor/md:SingleSignOnService');

        if (0 === count($result)) {
            // no SingleSignOnService entry for this entityID in metadata
            throw new MetadataParserException("entity not found in metadata, or no SingleSignOnService");
        }

        foreach ($result as $ep) {
            array_push($md['SingleSignOnService'], array("Binding" => (string) $ep['Binding'], "Location" => (string) $ep['Location']));
        }

        $result = $e->xpath('//md:EntityDescriptor[@entityID="' . $entityId . '"]/md:IDPSSODescriptor/md:KeyDescriptor');
        if (0 === count($result)) {
            // no KeyDescriptor entry for this entityID in metadata
            throw new MetadataParserException("entity not found in metadata, or no KeyDescriptor");
        }

        foreach ($result as $cd) {
            $certData = new CertParser((string) $cd->children("http://www.w3.org/2000/09/xmldsig#")->KeyInfo->X509Data->X509Certificate);
            array_push($md['certData'], $certData->toBase64());
        }

        return $md;
    }

    public static function sp($file, $entityId)
    {
        $e = @simplexml_load_file($file);
        if (FALSE === $e) {
            throw new MetadataParserException("unable to read metadata file");
        }

        $e->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $result = $e->xpath('//md:EntityDescriptor[@entityID="' . $entityId . '"]/md:SPSSODescriptor/md:AssertionConsumerService');
        if (0 === count($result)) {
            // no AssertionConsumerService entry for this entityID in metadata
            throw new MetadataParserException("entity not found in metadata, or no AssertionConsumerService");
        }

        $md = array("AssertionConsumerService" => array());
        foreach ($result as $ep) {
            array_push($md['AssertionConsumerService'], array("Binding" => (string) $ep['Binding'], "Location" => (string) $ep['Location'], "index" => (int) $e['index']));
        }

        return $md;
    }
}

class MetadataParserException extends \Exception
{
}
