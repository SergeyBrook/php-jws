<?php
/**
 * SBrook\JWS\Jws
 */

namespace SBrook\JWS;

use SBrook\JWS\Exception\JwsException;

/**
 * Class Jws
 * @package SBrook\JWS
 */
abstract class Jws {
	abstract function sign(array $payload, array $header = []);
	abstract function verify(string $jws): bool;

	/**
	 * @param string $jws
	 * @return array
	 * @throws JwsException
	 */
	public function getHeader(string $jws): array {
		if ($jws) {
			list($h, , ) = explode(".", $jws);
			$header = json_decode(base64_decode($h), true);
			if (is_null($header)) {
				throw new JwsException("Error while parsing JWS header", 2);
			} else {
				return $header;
			}
		} else {
			throw new JwsException("JWS can't be an empty string", 1);
		}
	}

	/**
	 * @param string $jws
	 * @return mixed
	 * @throws JwsException
	 */
	public function getPayload(string $jws) {
		if ($jws) {
			list(, $p, ) = explode(".", $jws);
			$payload = json_decode(base64_decode($p), true);
			if (is_null($payload)) {
				throw new JwsException("Error while parsing JWS payload", 3);
			} else {
				return $payload;
			}
		} else {
			throw new JwsException("JWS can't be an empty string", 1);
		}
	}
}
