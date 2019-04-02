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
	/**
	 * Create JWS from payload and optional header and sign it.
	 * @param array $payload Payload data.
	 * @param array $header Header data (optional).
	 * @return string JWS.
	 */
	abstract function sign(array $payload, array $header = []): string;

	/**
	 * Verify JWS signature.
	 * @param string $jws JWS.
	 * @return bool TRUE on valid signature or FALSE on invalid.
	 */
	abstract function verify(string $jws): bool;

	/**
	 * Get JWS header.
	 * @param string $jws JWS.
	 * @return array Decoded JWS header.
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
	 * Get JWS payload.
	 * @param string $jws JWS.
	 * @return array Decoded JWS payload.
	 * @throws JwsException
	 */
	public function getPayload(string $jws): array {
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
