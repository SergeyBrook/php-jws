<?php
/**
 * SBrook\JWS\JwsMac
 */

namespace SBrook\JWS;

use SBrook\JWS\Exception\JwsException;

/**
 * Class JwsMac
 * @package SBrook\JWS
 */
class JwsMac extends Jws implements Symmetric {
	/**
	 * JWS signature secret key.
	 * @var string
	 */
	private $secretKey = "";

	/**
	 * Algorithms map JWS => hash_hmac().
	 *  0-th element is a default.
	 *
	 * JWS signature algorithms (RFC 7518, Section 3.2) - "alg":
	 *  HS256: HMAC using SHA-256 - Min recommended key length: 32 bytes
	 *	HS384: HMAC using SHA-384 - Min recommended key length: 48 bytes
	 *	HS512: HMAC using SHA-512 - Min recommended key length: 64 bytes
	 *
	 * @var array
	 */
	private $algos = [
		"HS256" => "SHA256",
		"HS384" => "SHA384",
		"HS512" => "SHA512"
	];

	/**
	 * JwsMac constructor.
	 * @param string $key JWS signature secret key.
	 * @throws JwsException
	 */
	public function __construct(string $key) {
		if (strlen($key) > 0) {
			$this->secretKey = $key;
		} else {
			throw new JwsException("Secret key can't be an empty string", 10);
		}
	}

	/**
	 * JwsMac destructor.
	 */
	public function __destruct() {
		unset(
			$this->secretKey,
			$this->algos
		);
	}

	/**
	 * Set JWS signature secret key - overwrites one set in constructor.
	 * @param string $key JWS signature secret key.
	 * @param string $pass Not in use.
	 * @return bool TRUE on success or FALSE on failure.
	 */
	public function setSecretKey(string $key, string $pass = ""): bool {
		$result = false;
		if (strlen($key) > 0) {
			$this->secretKey = $key;
			$result = true;
		}
		return $result;
	}

	public function sign(array $payload, array $header = []) {}

	public function verify(string $jws): bool {}

	/**
	 * Create JWS signature.
	 * @param string $header Encoded header.
	 * @param string $payload Encoded payload.
	 * @return bool|string Signature. String containing JWS signature or bool FALSE on failure.
	 */
	private function createSignature(string $header, string $payload) {
		$result = false;
		$h = json_decode(base64_decode($header), true);
		if (is_array($h) && array_key_exists("alg", $h)) {
			$algo = strtoupper($h["alg"]);
			if (array_key_exists($algo, $this->algos) && strlen($this->secretKey) > 0) {
				$result = base64_encode(hash_hmac($this->algos[$algo], $header . "." . $payload, $this->secretKey, true));
			}
		}
		return $result;
	}
}
