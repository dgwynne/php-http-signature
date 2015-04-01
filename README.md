# php-http-signature

HTTP Signature Authentication library for PHP that has client and
server components for Joyent's HTTP Signature Scheme, as specified
at http://tools.ietf.org/html/draft-cavage-http-signatures-00 and
implemented at https://github.com/joyent/node-http-signature.

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
    file_get_contents($res['params']['keyId']), 'rsa') == FALSE) {
	// It's funny how much PHP sucks at HTTP things
	die("Unauthorized");
}

```
