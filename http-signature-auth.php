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

class HTTPSignature {

	static function parse(array $headers, array $options = array())
	{
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

		$headers['request-line'] = sprintf("%s %s %s", $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $_SERVER['SERVER_PROTOCOL']);

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

		$sign = array();
		foreach ($params['headers'] as $header) {
			$sign[] = $header === 'request-line' ? $headers['request-line'] : sprintf("%s: %s", $header, $headers[$header]);
		}

		return (array('scheme' => $scheme, 'params' => $params, 'signingString' => implode("\n", $sign)));
	}

	static function verify(array $res, $key)
	{
		if (!is_string($key)) {
			throw new Exception('key is not a string');
		}

		$alg = explode('-', $res['params']['algorithm'], 2);
		if (sizeof($alg) != 2) {
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
		switch ($alg[0]) {
		case 'rsa':
			$map = array('sha1' => OPENSSL_ALGO_SHA1, 'sha256' => OPENSSL_ALGO_SHA256, 'sha512' => OPENSSL_ALGO_SHA512);
			if (!array_key_exists($alg[1], $map)) {
				throw new InvalidAlgorithmError('unsupported algorithm');
			}
			$pkey = openssl_get_publickey($key);
			if ($pkey === FALSE) {
				throw new Exception('key could not be parsed');
			}

			$rv = openssl_verify($res['signingString'], base64_decode($res['params']['signature']), $pkey, $map[$alg[1]]);
			openssl_free_key($pkey);

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

	static function sign(array &$headers = array(), array $options = array())
	{
		if (!array_key_exists('keyId', $options)) {
			throw new Exception('keyId option is missing');
		} elseif (!is_string($options['keyId'])) {
			throw new Exception('keyId option is not a string');
		}
		if (!array_key_exists('key', $options)) {
			throw new Exception('key option is missing');
		} elseif (!is_string($options['key'])) {
			throw new Exception('key option is not a string');
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

		if (!array_key_exists('algorithm', $options)) {
			$options['algorithm'] = 'rsa-sha256';
		}

		if (!array_key_exists('date', $headers)) {
			$headers['date'] = date(DATE_RFC1123);
		}
		/* XXX */
		$headers['request-line'] = sprintf("%s %s %s", $_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $_SERVER['SERVER_PROTOCOL']);

		$sign = array();
		foreach ($options['headers'] as $header) {
			if (!array_key_exists($header, $headers)) {
				throw new MissingHeaderError("$header was not in the request");
			}
			$sign[] = $header === 'request-line' ? $headers['request-line'] : sprintf("%s: %s", $header, $headers[$header]);
		}
		$data = join("\n", $sign);

		$alg = explode('-', $options['algorithm'], 2);
		if (sizeof($alg) != 2) {
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
		switch ($alg[0]) {
		case 'rsa':
			$map = array('sha1' => OPENSSL_ALGO_SHA1, 'sha256' => OPENSSL_ALGO_SHA256, 'sha512' => OPENSSL_ALGO_SHA512);
			if (!array_key_exists($alg[1], $map)) {
				throw new InvalidAlgorithmError('unsupported algorithm');
			}
			$key = openssl_get_privatekey($options['key']);
			if ($key === FALSE) {
				throw new Exception('key option could not be parsed');
			}

			if (openssl_sign($data, $signature, $key, $map[$alg[1]]) === FALSE) {
				throw new Exception('unable to sign');
			}
			break;

		case 'hmac':
			$signature = hash_hmac($alg[1], $data, $options['key'], true);
			break;
		default:
			throw new InvalidAlgorithmError("unsupported algorithm");
		}
		unset($headers['request-line']);
		$headers['authorization'] = sprintf('Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"',
		    $options['keyId'], $options['algorithm'], implode(' ', $options['headers']),
		    base64_encode($signature));
	}
}
