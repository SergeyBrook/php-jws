<?php
/**
 * SBrook\JWS\Exception\MacException
 */

namespace SBrook\JWS\Exception;

use Exception;

/**
 * Class MacException
 * @package SBrook\JWS\Exception
 */
class MacException extends Exception {
	// Redefine the exception so message isn't optional:
	public function __construct($message, $code = 0, Exception $previous = null) {
		// Some code

		// Make sure everything is assigned properly:
		parent::__construct($message, $code, $previous);
	}

	// Custom string representation of object:
	public function __toString() {
		return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
	}
}
