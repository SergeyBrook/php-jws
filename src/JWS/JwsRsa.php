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
class JwsRsa extends Jws implements Asymmetric {

	public function __destruct() {}

	public function setPrivateKey(string $key, string $pass = ""): bool {}

	public function setPublicKey(string $key): bool {}

	public function sign(array $payload, array $header = []) {}

	public function verify(string $jws): bool {}
}
