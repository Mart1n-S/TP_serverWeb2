<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$pseudo = $_POST['pseudo'] ?? null;
if (!$pseudo) {
    http_response_code(400);
    exit("Pseudo manquant");
}

$secret = "supersecret"; // identique au Lua côté NGINX

$payload = [
    "sub" => $pseudo,
    "iat" => time(),
    "exp" => time() + 1800 // expire dans 30 minutes
];

$jwt = JWT::encode($payload, $secret, 'HS256');
error_log("✅ Pseudo reçu : $pseudo");
error_log("✅ JWT généré : $jwt");

setcookie("auth_token", $jwt, [
    'expires' => time() + 1800,
    'path' => '/',
    'secure' => true,
    'httponly' => false,
    'samesite' => 'Lax'
]);

header("Location: /");
exit;
