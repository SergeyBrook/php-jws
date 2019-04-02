<?php
/**
 * JWS-RSA example
 * Run from CLI.
 */

use SBrook\JWS\JwsRsa;
use SBrook\JWS\Exception\JwsException;

// Stand-alone:
require_once("../src/autoload.php");
// Composer:
//require_once("../vendor/autoload.php");

$exitCode = 0;

$prvOne = "file://./cert/prv-one.key";
$prvPas = "TEBtYjByZ2hpbmk=";

$pubOne = "file://./cert/pub-one.crt";
$pubTwo = "file://./cert/pub-two.crt";

// For JWS registered header parameter names see (RFC 7515, Section 4.1)
$header = [
	"typ" => "JWT",
	"alg" => "",
	"x5u" => ""
];

// For JWT registered claim names see (RFC 7519, Section 4.1)
$payloadData = [
	"iss" => "https://issuer.com",		// Issuer
	"sub" => "subject@something.com",	// Subject
	"aud" => "https://audience.com",	// Audience
	"exp" => time() + 86400,			// Expiration Time
	"nbf" => time(),					// Not Before
	"iat" => time(),					// Issued At
	"jti" => uniqid()					// JWT ID
];

try {
	// Create JwsRsa instance:
	$jws = new JwsRsa();

	// Sign JWT with private key ($prvOne):
	$jws->setPrivateKey($prvOne, base64_decode($prvPas));
	$jwt = $jws->sign(json_encode($payloadData), $header);
	echo "\n--- BEGIN JWT ---\n".$jwt."\n---- END JWT ----\n";

	// Verify JWT with right public key ($pubOne):
	$jws->setPublicKey($pubOne);
	$v = $jws->verify($jwt);
	echo "\nVerifying JWT with right public key:\n";
	echo "JWT is ".($v ? "VALID" : "NOT VALID")."\n";

	// Verify JWT with wrong public key ($pubTwo):
	$jws->setPublicKey($pubTwo);
	$v = $jws->verify($jwt);
	echo "\nVerifying JWT with wrong public key:\n";
	echo "JWT is ".($v ? "VALID" : "NOT VALID")."\n";

	// Get JWT header:
	$h = $jws->getHeader($jwt);
	echo "\nHeader => ";
	print_r($h);

	// Get JWT payload:
	$p = json_decode($jws->getPayload($jwt), true);
	echo "\nPayload => ";
	print_r($p);
} catch (JwsException $e) {
	$exitCode = 1;

	do {
		echo "Error (".$e->getCode()."): ".$e->getMessage()."\n\tIn file: ".$e->getFile()." line: ".$e->getLine()."\n";
	} while ($e = $e->getPrevious());
}

exit($exitCode);

