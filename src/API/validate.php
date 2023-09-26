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


?>