<?php
/**
 * SBrook\JWS\JwsRsa
 */

namespace SBrook\JWS;

use SBrook\JWS\Exception\JwsException;

/**
 * Class JwsRsa
 * @package SBrook\JWS
 */
class JwsRsa extends Jws implements Asymmetric
{
	/**
	 * JWS signature private key.
	 * @var resource
	 */
	protected $privateKey = false;

	/**
	 * JWS signature public key.
	 * @var resource
	 */
	protected $publicKey = false;

	/**
	 * Default signature algorithm.
	 * @var string
	 */
	protected $defaultAlgo = "RS256";

	/**
	 * Signature algorithms map JWS => openssl_sign() / openssl_verify().
	 *
	 * JWS signature algorithms (RFC 7518, Section 3.3) - "alg":
	 *  RS256: RSASSA-PKCS1-v1_5 using SHA-256
	 *  RS384: RSASSA-PKCS1-v1_5 using SHA-384
	 *  RS512: RSASSA-PKCS1-v1_5 using SHA-512
	 *
	 * @var array
	 */
	protected $algos = [
		"RS256" => OPENSSL_ALGO_SHA256,
		"RS384" => OPENSSL_ALGO_SHA384,
		"RS512" => OPENSSL_ALGO_SHA512
	];

	/**
	 * JwsRsa destructor.
	 */
	public function __destruct()
	{
		if ($this->privateKey) {
			openssl_pkey_free($this->privateKey);
		}

		if ($this->publicKey) {
			openssl_pkey_free($this->publicKey);
		}

		unset(
			$this->defaultAlgo,
			$this->algos
		);
	}

	/**
	 * Set private key - overwrites previously set key.
	 * @param string $key Private key. Same as openssl_pkey_get_private "key" parameter (http://php.net/manual/en/function.openssl-pkey-get-private.php).
	 * @param string $pass (Optional) Private key password. Same as openssl_pkey_get_private "passphrase" parameter (http://php.net/manual/en/function.openssl-pkey-get-private.php).
	 * @return bool TRUE on success or FALSE on failure.
	 */
	public function setPrivateKey(string $key, string $pass = ""): bool {
		$result = false;

		if ($this->privateKey) {
			openssl_pkey_free($this->privateKey);
		}

		$this->privateKey = openssl_pkey_get_private($key, $pass);
		if ($this->privateKey) {
			$result = true;
		}

		return $result;
	}

	/**
	 * Set public key - overwrites previously set key.
	 * @param string $key Public key. Same as openssl_pkey_get_public "certificate" parameter (http://php.net/manual/en/function.openssl-pkey-get-public.php).
	 * @return bool TRUE on success or FALSE on failure.
	 */
	public function setPublicKey(string $key): bool {
		$result = false;

		if ($this->publicKey) {
			openssl_pkey_free($this->publicKey);
		}

		$this->publicKey = openssl_pkey_get_public($key);
		if ($this->publicKey) {
			$result = true;
		}

		return $result;
	}

	/**
	 * Create JWS from payload and optional header and sign it.
	 * @param string $payload Payload.
	 * @param array $header (Optional) Header data.
	 * @return string JWS.
	 * @throws JwsException
	 */
	public function sign(string $payload, array $header = []): string {
		if ($this->privateKey) {
			if (strlen(trim($payload)) > 0) {
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

					$signature = null;
					$v = openssl_sign($h . "." . $p, $signature, $this->privateKey, $this->algos[$header["alg"]]);
					if ($v) {
						return $h . "." . $p . "." . base64_encode($signature);
					} else {
						throw new JwsException($this->getOpensslErrors(), 20);
					}
				} else {
					throw new JwsException("Requested unknown signature algorithm in header", 13);
				}
			} else {
				throw new JwsException("Payload can't be an empty string", 12);
			}
		} else {
			throw new JwsException("Private key is not set", 19);
		}
	}

	/**
	 * Verify JWS signature.
	 * @param string $jws JWS.
	 * @return bool TRUE on valid signature, FALSE on invalid.
	 * @throws JwsException
	 */
	public function verify(string $jws): bool {
		if ($this->publicKey) {
			if (strlen(trim($jws)) > 0) {
				list($h, $p, $s) = explode(".", $jws);

				if ($this->isValidHeader($h)) {
					$header = json_decode(base64_decode($h, true), true);

					$v = openssl_verify($h . "." . $p, base64_decode($s, true), $this->publicKey, $this->algos[strtoupper($header["alg"])]);
					if ($v == 1) {
						return true;
					} else if ($v == 0) {
						return false;
					} else {
						throw new JwsException($this->getOpensslErrors(), 20);
					}
				} else {
					throw new JwsException("Invalid JWS header", 11);
				}
			} else {
				throw new JwsException("JWS can't be an empty string", 1);
			}
		} else {
			throw new JwsException("Public key is not set", 18);
		}
	}

	/**
	 * Check validity of signature algorithm.
	 * @param string $algorithm Algorithm name.
	 * @return bool TRUE on valid algorithm, FALSE on invalid.
	 */
	protected function isValidAlgorithm(string $algorithm): bool {
		return array_key_exists(strtoupper($algorithm), $this->algos);
	}

	/**
	 * Get openssl error queue.
	 * @return string Openssl error messages separated by space.
	 */
	protected function getOpensslErrors(): string {
		$message = "";
		while ($m = openssl_error_string()) {
			$message .= $m." ";
		}
		return trim($message);
	}
}
