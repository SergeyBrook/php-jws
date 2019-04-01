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
	public function setSecretKey(string $key, string $pass = ""): bool;
}
