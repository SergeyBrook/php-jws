<?php
/**
 * SBrook\JWS\Asymmetric
 */

namespace SBrook\JWS;

/**
 * Interface Asymmetric
 * @package SBrook\JWS
 */
interface Asymmetric {
	/**
	 * Set private key.
	 * @param string $key Private key.
	 * @param string $pass (Optional) Private key password.
	 * @return bool TRUE on success or FALSE on failure.
	 */
	public function setPrivateKey(string $key, string $pass = ""): bool;

	/**
	 * Set public key.
	 * @param string $key Public key.
	 * @return bool TRUE on success or FALSE on failure.
	 */
	public function setPublicKey(string $key): bool;
}
