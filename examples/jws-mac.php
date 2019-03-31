<?php
/**
 * JWS-RSA example
 */

use SBrook\JWS\Mac;
use SBrook\JWS\Exception\MacException;

require_once("../src/autoload.php");

$exitCode = 0;

try {
	$jws= new Mac();
} catch (MacException $e) {
	do {
		echo "Error (".$e->getCode()."): ".$e->getMessage()."\n\tIn file: ".$e->getFile()." line: ".$e->getLine()."\n";
	} while ($e = $e->getPrevious());
	$exitCode = 1;
}

exit($exitCode);
