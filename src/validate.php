<?php

function validateEmail($mail) {
    if(strlen($mail) > 254) return false;
    return preg_match('/^\\w+([\\.\\+-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,24})+$/', $mail);
}

function validatePassword($pw) {
    if(strlen($pw) < 8) return false;
    if(strlen($pw) > 254) return false;
    if(!preg_match('#[A-Z]+#', $pw)) return false;
    if(!preg_match('#[a-z]+#', $pw)) return false;
    if(!preg_match('#[0-9]+#', $pw)) return false;
    return true;
}

function validateVeriCode($code) {
    return preg_match('/^[0-9]{6}$/', $code);
}

function validateCaptchaChal($captcha) {
    return preg_match('/^[a-f0-9]{32}$/', $captcha);
}

function validateCaptchaResp($captcha) {
    return preg_match('/^[a-np-zA-NP-Z1-9]{4}$/', $captcha);
}

function validateApiKey($apiKey) {
    return preg_match('/^[a-f0-9]{64}$/', $apiKey);
}

function validateApiKeyDescription($desc) {
    return preg_match('/^[a-zA-Z0-9 ]{1,255}$/', $desc);
}

function validate2FA($code) {
    return preg_match('/^[0-9]{6}$/', $code);
}

?>