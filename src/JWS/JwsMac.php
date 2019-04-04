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
	protected $secretKey = "";

	/**
	 * Default signature algorithm.
	 * @var string
	 */
	protected $defaultAlgo = "HS256";

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
	protected $algos = [
		"HS256" => "SHA256",
		"HS384" => "SHA384",
		"HS512" => "SHA512"
	];

	/**
	 * JwsMac constructor.
	 * @param string $key - JWS signature secret key.
	 * @throws JwsException
	 * TODO: Validate $key is string.
	 */
	public function __construct($key) {
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
			$this->defaultAlgo,
			$this->algos
		);
	}

	/**
	 * Set JWS signature secret key - overwrites previously set key.
	 * @param string $key - JWS signature secret key.
	 * @param $pass - (Optional) Not in use.
	 * @return bool - TRUE on success, FALSE on failure.
	 * TODO: Validate $key is string.
	 */
	public function setSecretKey($key, $pass = "") {
		$result = false;

		if (strlen($key) > 0) {
			$this->secretKey = $key;
			$result = true;
		}

		return $result;
	}

	/**
	 * Create JWS from payload and optional header and sign it.
	 * @param string $payload - Payload.
	 * @param array $header - (Optional) Header data.
	 * @return string - JWS.
	 * @throws JwsException
	 * TODO: Validate $header is array.
	 */
	public function sign($payload, $header = []) {
		if (is_string($payload)) {
			if (strlen($payload) > 0) {
				// Remove empty header parameters:
				foreach ($header as $key => $value) {
					if (!$value) {
						unset($header[$key]);
					}
				}

				// If not specified, set default signature algorithm:
				if (!array_key_exists("alg", $header)) {
					$header["alg"] = $this->defaultAlgo;
				}

				// Don't trust anyone:
				$header["alg"] = strtoupper($header["alg"]);

				if ($this->isValidAlgorithm($header["alg"])) {
					$h = base64_encode(json_encode($header));
					$p = base64_encode($payload);

					return $h . "." . $p . "." . base64_encode(hash_hmac($this->algos[$header["alg"]], $h . "." . $p, $this->secretKey, true));
				} else {
					throw new JwsException("Requested unknown signature algorithm in header", 14);
				}
			} else {
				throw new JwsException("Payload can't be an empty string", 13);
			}
		} else {
			throw new JwsException("Payload should be a string", 12);
		}
	}

	/**
	 * Verify JWS signature.
	 * @param string $jws - JWS.
	 * @return bool - TRUE on valid signature, FALSE on invalid.
	 * @throws JwsException
	 * TODO: Validate $jws is string.
	 */
	public function verify($jws) {
		if (strlen(trim($jws)) > 0) {
			list($h, $p, $s) = explode(".", $jws);

			if ($this->isValidHeader($h)) {
				$header = json_decode(base64_decode($h, true), true);

				return hash_equals(base64_decode($s, true), hash_hmac($this->algos[strtoupper($header["alg"])], $h . "." . $p, $this->secretKey, true));
			} else {
				throw new JwsException("Invalid JWS header", 11);
			}
		} else {
			throw new JwsException("JWS can't be an empty string", 1);
		}
	}

	/**
	 * Check validity of signature algorithm.
	 * @param string $algorithm - Algorithm name.
	 * @return bool - TRUE on valid algorithm, FALSE on invalid.
	 */
	protected function isValidAlgorithm($algorithm) {
		return is_string($algorithm) && array_key_exists(strtoupper($algorithm), $this->algos);
	}
}
