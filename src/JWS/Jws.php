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
	 * @param string $payload Payload.
	 * @param array $header Header data (optional).
	 * @return string JWS.
	 */
	abstract public function sign(string $payload, array $header = []): string;

	/**
	 * Verify JWS signature.
	 * @param string $jws JWS.
	 * @return bool TRUE on valid signature, FALSE on invalid.
	 */
	abstract public function verify(string $jws): bool;

	/**
	 * Check validity of signature algorithm.
	 * @param string $algorithm
	 * @return bool TRUE on valid algorithm, FALSE on invalid.
	 */
	abstract protected function isValidAlgorithm(string $algorithm): bool;

	/**
	 * Get JWS header.
	 * @param string $jws JWS.
	 * @return array Decoded JWS header.
	 * @throws JwsException
	 */
	public function getHeader(string $jws): array {
		if ($jws) {
			list($h, , ) = explode(".", $jws);
			$header = json_decode(base64_decode($h, true), true);
			if (is_null($header)) {
				throw new JwsException("Error while decoding JWS header", 2);
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
	 * @return string Decoded JWS payload.
	 * @throws JwsException
	 */
	public function getPayload(string $jws): string {
		if ($jws) {
			list(, $p, ) = explode(".", $jws);
			$payload = base64_decode($p, true);
			if ($payload) {
				return $payload;
			} else {
				throw new JwsException("Error while decoding JWS payload", 3);
			}
		} else {
			throw new JwsException("JWS can't be an empty string", 1);
		}
	}

	/**
	 * Check validity of JWS header.
	 * @param string|array $header JWS header (encoded|decoded).
	 * @return bool TRUE on valid JWS header, FALSE on invalid.
	 */
	protected function isValidHeader($header): bool {
		// If encoded header - decode it:
		if (is_string($header)) {
			$header = json_decode(base64_decode($header, true), true);
		}
		// The only required JWS header parameter is "alg":
		return is_array($header) && array_key_exists("alg", $header) && $this->isValidAlgorithm($header["alg"]);
	}
}
