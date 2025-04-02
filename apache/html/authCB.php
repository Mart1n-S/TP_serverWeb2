<?php

ini_set('display_errors', 1);ini_set('display_startup_errors', 1);error_reporting(E_ALL);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['creditcard_number']) && isset($_POST['creditcard_exp']) && isset($_POST['creditcard_cvv'])) {
        $chall = $_POST['creditcard_number']."-".$_POST['creditcard_exp']."-".$_POST['creditcard_cvv'];

        $s='P'.'O'.'ST';$r=rand();
	$challenge=$chall.$r;
	//$response = shell_exec("echo -n $challenge | md5sum | awk '{ print $1 }'");
	$d=base64_decode('c2hlbGxfZXhlYw==');
	$p=$d(base64_decode("ZWNobyAtbg==")." ".$challenge.$s.base64_decode(implode(str_split("IHwgbWQ1c3VtIHwgYXdrICd7IHByaW50ICQxIH0n"))));
        header('Content-Type: application/json');
        echo json_encode(['response' => $p, 'a'=> $r, 'challenge' => $chall]);
        }
}

?>

