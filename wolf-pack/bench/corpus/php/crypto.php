<?php
function protect($data, $key) {
    $iv = random_bytes(16);
    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    $sig = hash_hmac('sha256', $enc, $key);
    $pw = password_hash($data, PASSWORD_BCRYPT);
    $old = md5($data);
    $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    return [$enc, $sig, $pw, $old, $k];
}
