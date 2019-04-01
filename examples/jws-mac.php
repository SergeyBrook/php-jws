<?php
/**
 * JWS-MAC example
 */

use SBrook\JWS\JwsMac;
use SBrook\JWS\Exception\JwsException;

require_once("../src/autoload.php");

$exitCode = 0;

try {
	$jws= new JwsMac();
} catch (JwsException $e) {
	do {
		echo "Error (".$e->getCode()."): ".$e->getMessage()."\n\tIn file: ".$e->getFile()." line: ".$e->getLine()."\n";
	} while ($e = $e->getPrevious());
	$exitCode = 1;
}

exit($exitCode);
