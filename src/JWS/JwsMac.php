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
	 * Default signature algorithm.
	 * @var string
	 */
	private $defaultAlgo = "HS256";

	/**
	 * Signature algorithms map JWS => hash_hmac().
	 *
	 * JWS signature algorithms (RFC 7518, Section 3.2) - "alg":
	 *  HS256: HMAC using SHA-256 - Min recommended key length: 32 bytes
	 *  HS384: HMAC using SHA-384 - Min recommended key length: 48 bytes
	 *  HS512: HMAC using SHA-512 - Min recommended key length: 64 bytes
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
	 * @param string $pass (Optional) Not in use.
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

	/**
	 * Create JWS from payload and optional header and sign it.
	 * @param array $payload Payload data.
	 * @param array $header (Optional) Header data.
	 * @return string JWS.
	 * @throws JwsException
	 */
	public function sign(array $payload, array $header = []): string {
		if (count($payload) > 0) {
			// Remove empty header parameters:
			foreach ($header as $key => $value) {
				if (!$value) {
					unset($header[$key]);
				}
			}

			if (array_key_exists("alg", $header)) {
				$header["alg"] = strtoupper($header["alg"]);
			} else {
				$header["alg"] = $this->defaultAlgo;
			}

			if (array_key_exists($header["alg"], $this->algos)) {
				$h = base64_encode(json_encode($header));
				$p = base64_encode(json_encode($payload));

				try {
					return $h.".".$p.".".$this->createSignature($h, $p);
				} catch (JwsException $e) {
					throw $e;
				}
			} else {
				throw new JwsException("Requested unknown signature algorithm in header", 15);
			}
		} else {
			throw new JwsException("Payload can't be an empty array", 14);
		}
	}

	/**
	 * Verify JWS signature.
	 * @param string $jws JWS.
	 * @return bool TRUE on valid signature or FALSE on invalid.
	 * @throws JwsException
	 */
	public function verify(string $jws): bool {
		if ($jws) {
			list($h, $p, $s) = explode(".", $jws);

			try {
				return $s === $this->createSignature($h, $p);
			} catch (JwsException $e) {
				throw $e;
			}
		} else {
			throw new JwsException("JWS can't be an empty string", 1);
		}
	}

	/**
	 * Create JWS signature.
	 * @param string $header Encoded header.
	 * @param string $payload Encoded payload.
	 * @return string JWS signature.
	 * @throws JwsException
	 */
	private function createSignature(string $header, string $payload): string {
		if (strlen($payload) > 0) {
			$h = json_decode(base64_decode($header), true);

			if (is_null($h)) {
				throw new JwsException("Error while parsing JWS header", 2);
			} else {
				if (is_array($h) && array_key_exists("alg", $h)) {
					$algo = strtoupper($h["alg"]);

					if (array_key_exists($algo, $this->algos)) {
						return base64_encode(hash_hmac($this->algos[$algo], $header . "." . $payload, $this->secretKey, true));
					} else {
						throw new JwsException("Unknown signature algorithm in JWS header", 13);
					}
				} else {
					throw new JwsException("Invalid JWS header", 12);
				}
			}
		} else {
			throw new JwsException("JWS payload can't be an empty string", 11);
		}
	}
}
