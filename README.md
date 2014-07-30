# php-http-signature

Note: I've updated the source file and directory structure to follow psr-4 layout for autoloading as composer package.

For example in composer.json, you can add the following to autoload the class...

```
"repositories": {
    "http-signer": {
      "type": "package",
      "package": {
        "name": "gwynne/http-signer",
        "version": "1.0.0",
        "source": {
          "url": "https://github.com/58bits/php-http-signature",
          "type": "git",
          "reference": "7abfde5fc7ad29b62446fb59c967458f48227220"
        }
      }
    }
  },

"autoload": {
    "psr-4": {
      "Gwynne\\": "vendor/gwynne/http-signer/src/"
    }
  }
```

`composer install` would then automatically clone the repository into the following vendor directory...

```
── composer.json
├── composer.lock
└── vendor
    ├── autoload.php
    ├── composer
    └── gwynne
        └── http-signer
            ├── LICENSE
            ├── README.md
            └── src
                └── HTTPSignature.php
```

Using the signature class then becomes...

```
require 'vendor/autoload.php'; // Loads all vendor related 'requires'.

$date = gmdate(DATE_RFC1123);
$headers = array('date' => $date);

Gwynne\HTTPSignature::sign($headers, array(
    'key' => '46653e78ce9df4f2d9ae93gft5f5c281',
    'keyId' => '18KF2FGK6807ZQA9FGT4',
    'algorithm' => 'hmac-sha1'
));
```

(although this class should really contain instance members and be 'new'd' up when used.")

I've submitted a pull request to the author.

# Original README


HTTP Signature Authentication library for PHP that has client and server components for Joyent's HTTP Signature Scheme, as specified at http://tools.ietf.org/html/draft-cavage-http-signatures-00 and implemented at https://github.com/joyent/node-http-signature.  

## Usage

### Client

```php
require_once('http-signature-auth.php');

HTTPSignature::sign($headers, array(
	'key' => file_get_contents('./key.pem'),
	'keyId' => './key.pub'
));

// It's funny how much PHP sucks at HTTP things
$h = array();
foreach ($headers as $k => $v) {
	$h[] = "$k: $v";
}

$ch = curl_init("https://lolhost/");
curl_setopt($ch, CURLOPT_HTTPHEADER, $h);
curl_exec($ch);
curl_close($ch);
```

### Server

```php
require_once('http-signature-auth.php');

try {
	$res = HTTPSignature::parse(getallheaders());
} catch (HttpSignatureError $e) {
	die("HTTP Signature Error: " . $e->getMessage());
} catch (Exception $e) {
	die($e->getMessage();
}

if (HTTPSignature::verify($res,
    file_get_contents($res['params']['keyId'])) == FALSE) {
	// It's funny how much PHP sucks at HTTP things
	die("Unauthorized");
}

```
