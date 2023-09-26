<?php

require_once __DIR__.'/validate.php';

use Infinex\Exceptions\Error;
use Gregwar\Captcha\CaptchaBuilder;

class SignupAPI {
    private $log;
    private $amqp;
    private $pdo;
    private $rest;
    
    function __construct($log, $amqp, $pdo, $rest) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> rest = $rest;
        
        $this -> rest -> get('/captcha', [$this, 'getCaptcha']);
        $this -> rest -> post('/', [$this, 'register']);
        $this -> rest -> patch('/', [$this, 'verify']);
        
        $this -> log -> debug('Initialized sign up API');
    }
    
    public function register($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Cannot register a new account while logged in', 403);
        
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        if(!isset($body['captchaChallenge']))
            throw new Error('MISSING_DATA', 'captchaChallenge', 400);
        if(!isset($body['captchaResponse']))
            throw new Error('MISSING_DATA', 'captchaResponse', 400);
        
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        if(!validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
        if(!$this -> validateCaptchaChal($body['captchaChallenge']))
            throw new Error('VALIDATION_ERROR', 'captchaChallenge', 400);
        if(!$this -> validateCaptchaResp($body['captchaResponse']))
            throw new Error('VALIDATION_ERROR', 'captchaResponse', 400);
        if(isset($body['refid']) && !$this -> validateRefid($body['refid']))
            throw new Error('VALIDATION_ERROR', 'refid', 400);
        
        $email = strtolower($body['email']);
        
        $captchaReference = md5(CAPTCHA_SALT.strtolower($body['captchaResponse']).$email);
        if($captchaReference != $body['captchaChallenge'])
            throw new Error('INVALID_CAPTCHA', 'Invalid captcha code', 400);
        
        $hashedPassword = password_hash($body['password'], PASSWORD_DEFAULT);
        
        $this -> pdo -> beginTransaction();
        
        $task = array(
            ':email' => $email
        );
        
        $sql = 'SELECT uid
                FROM users
                WHERE email = :email
                FOR UPDATE';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($row) {
            $this -> pdo -> rollBack();
            throw new Error('ALREADY_EXISTS', 'There is already an account registered with this email address.', 409);
        }
    
        $task = array(
            ':email' => $email,
            ':password' => $hashedPassword
        );
        
        // Insert user
        $sql = 'INSERT INTO users (
            email,
            password,
            verified,
            register_time
        )
        VALUES (
            :email,
            :password,
            FALSE,
            CURRENT_TIMESTAMP
        )
        RETURNING uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        $uid = $row['uid'];
        
        // Generate verification code
        $generatedCode = sprintf('%06d', rand(0, 999999));
        
        $task = array(
            ':uid' => $uid,
            ':code' => $generatedCode
        );
        
        $sql = "INSERT INTO email_codes (
            uid,
            context,
            code
        )
        VALUES (
            :uid,
            'REGISTER_USER',
            :code
        )";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
        
        $this -> amqp -> pub(
            'registerUser',
            [
                'uid' => $uid,
                'refid' => isset($body['refid']) ? $body['refid'] : null
            ],
            [
                'affiliation' => true
            ]
        );
        
        // Send verification email
        $this -> amqp -> pub(
            'mail',
            [
                'uid' => $uid,
                'template' => 'register_user',
                'context' => [
                    'code' => $generatedCode
                ],
                'email' => $email
            ]
        );
    }
    
    public function getCaptcha($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        if(!isset($query['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        
        if(!validateEmail($query['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        
        $email = strtolower($query['email']);
        
        $phrase = substr(str_shuffle('abcdefghijklmnpqrstuvwxyz123456789'), 0, 4);
        $captcha = new CaptchaBuilder($phrase);
        $captcha -> build();
        
        return [
            'challenge' => md5(CAPTCHA_SALT.$phrase.$email),
            'img' => $captcha -> inline()
        ];
    }
    
    public function verify($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        if(!isset($body['code']))
            throw new Error('MISSING_DATA', 'code', 400);
        
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        if(!validateVeriCode($body['code']))
            throw new Error('VALIDATION_ERROR', 'code', 400);
        
        $email = strtolower($body['email']);
        
        $this -> pdo -> beginTransaction();
    
        $task = array(
            ':email' => $email,
            ':code' => $body['code']
        );
        
        $sql = "SELECT email_codes.codeid,
                users.uid
            FROM email_codes,
                users
            WHERE email_codes.code = :code
            AND email_codes.context = 'REGISTER_USER'
            AND users.email = :email
            AND email_codes.uid = users.uid
            FOR UPDATE OF email_codes";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(! $row) {
            $this -> pdo -> rollBack();
            throw new Error('INVALID_VERIFICATION_CODE', 'Invalid verification code', 401);
        }
        $uid = $row['uid'];
        
        $task = array(
            ':codeid' => $row['codeid']
        );
        
        $sql = 'DELETE FROM email_codes WHERE codeid = :codeid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $task = array(
            ':uid' => $uid
        );
        
        $sql = 'UPDATE users
            SET verified = TRUE
            WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
    }
    
    private function validateCaptchaChal($captcha) {
        return preg_match('/^[a-f0-9]{32}$/', $captcha);
    }

    private function validateCaptchaResp($captcha) {
        return preg_match('/^[a-np-zA-NP-Z1-9]{4}$/', $captcha);
    }

    private function validateRefid($refid) {
        if(!is_int($refid)) return false;
        if($refid < 1) return false;
        return true;
    }
}

?>