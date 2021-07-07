<?php
/*
 * Copyright (c) 2014 David Gwynne <david@gwynne.id.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

class HttpSignatureError extends Exception { };
class ExpiredRequestError extends HttpSignatureError { };
class InvalidHeaderError extends HttpSignatureError { };
class InvalidParamsError extends HttpSignatureError { };
class MissingHeaderError extends HttpSignatureError { };
class InvalidAlgorithmError extends HttpSignatureError { };
class KeyTypeError extends HttpSignatureError { };

class HTTPSignature {

	static function parse(array $inheaders, array $options = array())
	{
		$headers = array();
		foreach ($inheaders as $key => $value) {
			$headers[strtolower($key)] = $value;
		}
		if (!array_key_exists('authorization', $headers)) {
			throw new MissingHeaderError('no authorization header in the request');
		}
		$auth = $headers['authorization'];

		if (!array_key_exists('headers', $options)) {
			$options['headers'] = array(isset($headers['x-date']) ? 'x-date' : 'date');
		} else {
			if (!is_array($options['headers'])) {
				throw new Exception('headers option is not an array');
			}
			if (sizeof(array_filter($options['headers'], function ($a) { return (!is_string($a)); }))) {
				throw new Exception('headers option is not an array of strings');
			}
		}

		if (!array_key_exists('clockSkew', $options)) {
			$options['clockSkew'] = 300;
		} elseif (!is_numeric($options['clockSkew'])) {
			throw new Exception('clockSkew option is not numeric');
		}

		if (array_key_exists('algorithms', $options)) {
			if (!is_array($options['algorithms'])) {
				throw new Exception('algorithms option is not an array');
			}
			if (sizeof(array_filter($options['algorithms'], function ($a) { return (!is_string($a)); }))) {
				throw new Exception('algorithms option is not an array of strings');
			}
		}

		$headers['(request-target)'] = array_key_exists('requestTarget', $options) ?
		    $options['requestTarget'] :
		    sprintf("%s %s", strtolower($_SERVER['REQUEST_METHOD']), $_SERVER['REQUEST_URI']);

		foreach ($options['headers'] as $header) {
			if (!array_key_exists($header, $headers)) {
				throw new MissingHeaderError("$header was not in the request");
			}
		}

		$states = array(
			'start' => 0,
			'scheme' => 1,
			'space' => 2,
			'param' => 3,
			'quote' => 4,
			'value' => 5,
			'comma' => 6
		);

		$scheme = '';
		$params = array();

		$param = '';
		$value = '';
		$state = $states['start'];

		for ($i = 0; $i < strlen($auth); $i++) {
			$ch = $auth[$i];

			switch ($state) {
			case $states['start']:
				if (ctype_space($ch)) {
					break;
				}

				$state = $states['scheme'];
				/* FALLTHROUGH */
			case $states['scheme']:
				if (ctype_space($ch)) {
					$state = $states['space'];
				} else {
					$scheme .= $ch;
				}

				break;

			case $states['space'];
				if (ctype_space($ch)) {
					continue;
				}

				$state = $states['param'];
				/* FALLTHROUGH */
			case $states['param']:
				if ($ch === '=') {
					if ($param === '') {
						throw new InvalidHeaderError('bad param name');
					}
					if (array_key_exists($param, $params)) {
						throw new InvalidHeaderError('param specified again');
					}

					$state = $states['quote'];
					break;
				}
				if (!ctype_alpha($ch)) {
					throw new InvalidHeaderError('bad param format');
				}

				$param .= $ch;
				break;

			case $states['quote'];
				if ($ch !== '"') {
					throw new InvalidHeaderError('bad param format');
				}
				$state = $states['value'];
				break;

			case $states['value']:
				if ($ch === '"') {
					$params[$param] = $value;
					$param = '';
					$value = '';

					$state = $states['comma'];
					break;
				}

				$value .= $ch;
				break;

			case $states['comma']:
				if ($ch !== ',') {
					throw new InvalidHeaderError('bad param format');
				}

				$state = $states['param'];
				break;

			default:
				throw new Error('invalid state');
			}
		}

		if ($state !== $states['comma']) {
			throw new InvalidHeaderError("bad param format");
		}

		if ($scheme !== 'Signature') {
			throw new InvalidHeaderError('scheme was not "Signature"');
		}
		$required = array('keyId', 'algorithm', 'signature');
		foreach ($required as $param) {
			if (!array_key_exists($param, $params)) {
				throw new InvalidHeaderError("$param was not specified");
			}
		}

		if (array_key_exists('headers', $params)) {
			$params['headers'] = explode(' ', $params['headers']);
		} else {
			$params['headers'] = array(isset($headers['x-date']) ? 'x-date' : 'date');
		}

		foreach ($options['headers'] as $header) {
			if (!in_array($header, $params['headers'])) {
				throw new MissingHeaderError("$header was not a signed header");
			}
		}

		if (isset($options['algorithms']) && !in_array($params['algorithm'], $options['algorithms'])) {
			throw new InvalidParamsError($params['algorithm'] . " is not a supported algorithm");
		}

		$date = null;
		if (isset($headers['date'])) {
			$date = strtotime($headers['date']);
		} elseif (isset($headers['x-date'])) {
			$date = strtotime($headers['x-date']);
		}
		if (!is_null($date)) {
			if ($date === FALSE) {
				throw new InvalidHeaderError('unable to parse date header');
			}
			$skew = abs(time() - $date);
			if ($skew > $options['clockSkew']) {
				throw new ExpiredRequestError(sprintf("clock skew of %ds was greater than %ds", $skew, $options['clockSkew']));
			}
		}

		$headers['(keyid)'] = $params['keyId'];
		$headers['(algorithm)'] = $params['algorithm'];

		$sign = array();
		foreach ($params['headers'] as $header) {
			$sign[] = sprintf("%s: %s", $header, $headers[$header]);
		}

		return (array('scheme' => $scheme, 'params' => $params, 'signingString' => implode("\n", $sign)));
	}

	static function verify(array $res, $key, $keytype)
	{
		$freekey = FALSE;

		switch ($keytype) {
		case 'hmac':
			if (!is_string($key))
				throw new KeyTypeError('key is not a string');
			break;
		case 'rsa':
		case 'ecdsa':
			if (is_string($key)) {
				$key = openssl_get_publickey($key);
				if ($key === FALSE) {
					throw new KeyTypeError('key could not be parsed');
				}
				$freekey = TRUE;
			}
			$info = openssl_pkey_get_details($key);
			if ($info === FALSE) {
				throw new KeyTypeError('key is not a string or a valid key resource');
			}
			if ($keytype === 'rsa' && $info['type'] !== OPENSSL_KEYTYPE_RSA) {
				throw new KeyTypeError('key and keytype arguments do not match');
			} else if ($keytype === 'ecdsa' && $info['type'] !== OPENSSL_KEYTYPE_EC) {
				throw new KeyTypeError('key and keytype arguments do not match');
			}
			break;
		default:
			throw new KeyTypeError('unknown key type: ' . $keytype);
		}

		$alg = explode('-', $res['params']['algorithm'], 2);
		if (sizeof($alg) != 2) {
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
		if ($alg[0] != $keytype) {
			throw new InvalidAlgorithmError("algorithm type doesn't match key type");
		}
		switch ($alg[0]) {
		case 'rsa':
		case 'ecdsa':
			$map = array(
				'sha1' => OPENSSL_ALGO_SHA1,
				'sha256' => OPENSSL_ALGO_SHA256,
				'sha384' => OPENSSL_ALGO_SHA384,
				'sha512' => OPENSSL_ALGO_SHA512
			);
			if (!array_key_exists($alg[1], $map)) {
				throw new InvalidAlgorithmError('unsupported algorithm');
			}
			if ($alg[1] === 'sha1' && $alg[0] !== 'rsa') {
				throw new InvalidAlgorithmError('unsupported algorithm');
			}

			$rv = openssl_verify($res['signingString'], base64_decode($res['params']['signature']), $key, $map[$alg[1]]);
			if ($freekey)
				openssl_free_key($key);

			switch ($rv) {
			case 0:
				return (FALSE);
			case 1:
				return (TRUE);
			default:
				throw new Exception('key could not be verified');
			}
			break;

		case 'hmac':
			return (hash_hmac($alg[1], $res['signingString'], $key, true) === base64_decode($res['params']['signature']));
			break;
		default:
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
	}

	static function sign(&$headers = array(), array $options = array())
	{
		if (is_null($headers)) {
			$headers = array();
		} elseif (!is_array($headers)) {
			throw new Exception('headers are not an array');
		}

		if (!array_key_exists('keyId', $options)) {
			throw new Exception('keyId option is missing');
		} elseif (!is_string($options['keyId'])) {
			throw new Exception('keyId option is not a string');
		}
		if (!array_key_exists('key', $options)) {
			throw new Exception('key option is missing');
		}

		if (!array_key_exists('headers', $options)) {
			$options['headers'] = array('date');
		} else {
			if (!is_array($options['headers'])) {
				throw new Exception('headers option is not an array');
			}
			if (sizeof(array_filter($options['headers'], function ($a) { return (!is_string($a)); }))) {
				throw new Exception('headers option is not an array of strings');
			}
		}

		$key = FALSE;
		$freekey = FALSE;
		if (!array_key_exists('algorithm', $options)) {
			if (is_string($options['key'])) {
				$key = openssl_get_privatekey($options['key']);
				if ($key === FALSE) {
					error_log(openssl_error_string());
					throw new Exception('no algorithm given, and key option could not be parsed as a private key');
				}
				$freekey = TRUE;
			} else {
				$key = $options['key'];
			}
			$info = openssl_pkey_get_details($key);
			if ($info === FALSE) {
				throw new Exception('no algorithm given, and key option was not a valid private key');
			}
			switch ($info['type']) {
			case OPENSSL_KEYTYPE_RSA:
				$options['algorithm'] = 'rsa-sha256';
				break;
			case OPENSSL_KEYTYPE_EC:
				if ($info['bits'] <= 256)
					$options['algorithm'] = 'ecdsa-sha256';
				else if ($info['bits'] <= 384)
					$options['algorithm'] = 'ecdsa-sha384';
				else
					$options['algorithm'] = 'ecdsa-sha512';
				break;
			default:
				throw new Exception('no algorithm given, and key option is of unknown key type');
			}
		}

		if (!array_key_exists('date', $headers)) {
			$headers['date'] = date(DATE_RFC1123);
		}

		$headers['(request-target)'] = array_key_exists('requestTarget', $options) ?
		    $options['requestTarget'] :
		    sprintf("%s %s", strtolower($_SERVER['REQUEST_METHOD']), $_SERVER['REQUEST_URI']);
		$headers['(keyid)'] = $options['keyId'];
		$headers['(algorithm)'] = $options['algorithm'];

		$sign = array();
		foreach ($options['headers'] as $header) {
			if (!array_key_exists($header, $headers)) {
				throw new MissingHeaderError("$header was not in the request");
			}
			$sign[] = sprintf("%s: %s", $header, $headers[$header]);
		}
		$data = join("\n", $sign);

		$alg = explode('-', $options['algorithm'], 2);
		if (sizeof($alg) != 2) {
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
		switch ($alg[0]) {
		case 'rsa':
		case 'ecdsa':
			$map = array(
				'sha256' => OPENSSL_ALGO_SHA256,
				'sha384' => OPENSSL_ALGO_SHA384,
				'sha512' => OPENSSL_ALGO_SHA512
			);
			if (!array_key_exists($alg[1], $map)) {
				throw new InvalidAlgorithmError('unsupported algorithm');
			}
			if ($key === FALSE && is_string($options['key'])) {
				$key = openssl_get_privatekey($options['key']);
				if ($key === FALSE) {
					error_log(openssl_error_string());
					throw new Exception('key option could not be parsed');
				}
				$freekey = TRUE;
			}
			$info = openssl_pkey_get_details($key);
			if ($info === FALSE) {
				throw new Exception('key option was not a string or valid key resource');
			}
			if ($alg[0] === 'rsa' && $info['type'] !== OPENSSL_KEYTYPE_RSA) {
				throw new KeyTypeError('key and algorithm options do not match');
			} else if ($keytype === 'ecdsa' && $info['type'] !== OPENSSL_KEYTYPE_EC) {
				throw new KeyTypeError('key and algorithm options do not match');
			}

			if (openssl_sign($data, $signature, $key, $map[$alg[1]]) === FALSE) {
				throw new Exception('unable to sign');
			}

			if ($freekey)
				openssl_pkey_free($key);
			break;

		case 'hmac':
			if (!is_string($options['key'])) {
				throw new Exception('key option is not a string');
			}
			$signature = hash_hmac($alg[1], $data, $options['key'], true);
			break;
		default:
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
		unset($headers['(request-target)']);
		unset($headers['(keyid)']);
		unset($headers['(algorithm)']);
		$headers['authorization'] = sprintf('Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"',
		    $options['keyId'], $options['algorithm'], implode(' ', $options['headers']),
		    base64_encode($signature));
	}
}
