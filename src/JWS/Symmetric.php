<?php
/**
 * SBrook\JWS\Symmetric
 */

namespace SBrook\JWS;

/**
 * Interface Symmetric
 * @package SBrook\JWS
 */
interface Symmetric {
	/**
	 * Set secret key.
	 * @param string $key Secret key.
	 * @param string $pass (Optional) Secret key password.
	 * @return bool TRUE on success or FALSE on failure.
	 */
	public function setSecretKey(string $key, string $pass = ""): bool;
}
