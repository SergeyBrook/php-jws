<?php
/**
 * JWS-RSA example
 */

use SBrook\JWS\JwsRsa;
use SBrook\JWS\Exception\JwsException;

// Stand-alone:
require_once("../src/autoload.php");
// Composer:
//require_once("../vendor/autoload.php");

$exitCode = 0;

try {
	$jws= new JwsRsa();
} catch (JwsException $e) {
	$exitCode = 1;

	do {
		echo "Error (".$e->getCode()."): ".$e->getMessage()."\n\tIn file: ".$e->getFile()." line: ".$e->getLine()."\n";
	} while ($e = $e->getPrevious());
}

exit($exitCode);

