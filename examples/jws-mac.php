<?php
/**
 * JWS-MAC example
 * Run from CLI.
 */

use SBrook\JWS\JwsMac;
use SBrook\JWS\Exception\JwsException;

// Stand-alone:
require_once("../src/autoload.php");
// Composer:
//require_once("../vendor/autoload.php");

$exitCode = 0;

$secretOne = "8AA829AC3E1FAF5B75C1EC67A610670FFE56BF37";
$secretTwo = "6FB2486F46632DFC171B36ED64E9FA1BAE06FC29";

// For JWS registered header parameter names see (RFC 7515, Section 4.1)
$header = [
	"typ" => "JWT",
	"alg" => "",
	"cty" => ""
];

// For JWT registered claim names see (RFC 7519, Section 4.1)
$payload = [
	"iss" => "https://issuer.com",		// Issuer
	"sub" => "subject@something.com",	// Subject
	"aud" => "https://audience.com",	// Audience
	"exp" => time() + 86400,			// Expiration Time
	"nbf" => time(),					// Not Before
	"iat" => time(),					// Issued At
	"jti" => uniqid()					// JWT ID
];

try {
	// Create JwsMac instance:
	$jws = new JwsMac($secretOne);

	// Create and sign JWT:
	$jwt = $jws->sign($payload, $header);
	echo "\n--- BEGIN JWT ---\n".$jwt."\n---- END JWT ----\n";

	// Verify JWT with right secret key ($secretOne - already set in constructor):
	$v = $jws->verify($jwt);
	echo "\nVerifying JWT with right secret key:\n";
	echo "JWT is ".($v ? "VALID" : "NOT VALID")."\n";

	// Verify JWT with wrong secret key ($secretTwo):
	$jws->setSecretKey($secretTwo);
	$v = $jws->verify($jwt);
	echo "\nVerifying JWT with wrong secret key:\n";
	echo "JWT is ".($v ? "VALID" : "NOT VALID")."\n";

	// Get JWT header:
	$h = $jws->getHeader($jwt);
	echo "\nHeader => ";
	print_r($h);

	// Get JWT payload:
	$p = $jws->getPayload($jwt);
	echo "\nPayload => ";
	print_r($p);
} catch (JwsException $e) {
	$exitCode = 1;

	do {
		echo "Error (".$e->getCode()."): ".$e->getMessage()."\n\tIn file: ".$e->getFile()." line: ".$e->getLine()."\n";
	} while ($e = $e->getPrevious());
}

exit($exitCode);
