# Introduction
This tool exports JANUS data to JSON for both export purposes and checking the
data to see if the data contained within JANUS is valid.

# Installation
You can use [Composer](http://getcomposer.org/) to install the dependencies.

    $ composer install

# Configuration
Copy the `config/config.ini.defaults` to `config/config.ini` and modify it for
your setup, i.e.: set the database information and (export) paths. See the
explanation included in the template `config.ini.defaults` on what everything
means.

Do not forget to create the `export` directory, it needs to exist!

# Usage
You first have to run the `exportJanus.php` script which will create `JSON` 
files in the export directory:

* `saml20-idp-remote.json` which will contain information about the SAML IdPs
* `saml20-sp-remote.json` which will contain information about the SAML SPs
* `allAttributes.json` which will contain a `JSON` list from all the attributes
  used in JANUS's ARPs
* `entityLog.json` a log of the export process and problems found

The script `entityLogToHtml.php` converts the `entityLog.json` to a HTML 
version of the log making it easy to view the issues.
