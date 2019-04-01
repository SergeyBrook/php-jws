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
	public function setPrivateKey(string $key, string $pass = ""): bool;
	public function setPublicKey(string $key): bool;
}
