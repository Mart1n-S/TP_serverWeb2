<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;

// Vérifie que la requête est bien en POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: /jwt/login.html?error=method");
    exit;
}

$pseudo = $_POST['pseudo'] ?? null;
$motdepasse = $_POST['motdepasse'] ?? null;

if (!$pseudo || !$motdepasse) {
    header("Location: /jwt/login.html?error=missing");
    exit;
}

try {
    $db = new PDO("pgsql:host=donsecure-db;dbname=authCB", 'authcb', 'authcb');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $db->prepare("SELECT mot_de_passe_hash FROM users WHERE pseudo = :pseudo");
    $stmt->bindParam(':pseudo', $pseudo);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || !password_verify($motdepasse, $row['mot_de_passe_hash'])) {
        // Redirige avec un message d’erreur via paramètre GET
        header("Location: /jwt/login.html?error=1");
        exit;
    }


    // Lecture de la clé secrète
    $secretPath = '/var/www/html/jwt/jwt-secret.key';
    if (!file_exists($secretPath)) {
        throw new RuntimeException("Clé secrète introuvable");
    }
    $secret = trim(file_get_contents($secretPath));

    // Génération du JWT
    $payload = [
        "sub" => $pseudo,
        "iat" => time(),
        "exp" => time() + 1800 // 30 min
    ];

    $jwt = JWT::encode($payload, $secret, 'HS256');

    error_log("✅ Pseudo reçu : $pseudo");
    error_log("✅ JWT généré : $jwt");

    // Set du cookie
    setcookie("auth_token", $jwt, [
        'expires' => time() + 1800,
        'path' => '/',
        'secure' => true,
        'httponly' => false,
        'samesite' => 'Lax'
    ]);

    header("Location: /");
    exit;
} catch (Exception $e) {
    error_log("❌ Erreur serveur : " . $e->getMessage());
    header("Location: /jwt/login.html?error=server");
    exit;
}
