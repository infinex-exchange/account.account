<?php

use Infinex\Exceptions\Error;
use Gregwar\Captcha\CaptchaBuilder;

class SignupAPI {
    private $log;
    private $pdo;
    private $users;
    private $vc;
    
    function __construct($log, $pdo, $users, $vc) {
        $this -> log = $log;
        $this -> pdo = $pdo;
        $this -> users = $users;
        $this -> vc = $vc;
        
        $this -> log -> debug('Initialized sign up API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/signup/captcha', [$this, 'getCaptcha']);
        $rc -> post('/signup', [$this, 'register']);
        $rc -> patch('/signup', [$this, 'verify']);
    }
    
    public function register($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Cannot register a new account while logged in', 403);
        
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        if(!isset($body['captchaChallenge']))
            throw new Error('MISSING_DATA', 'captchaChallenge', 400);
        if(!isset($body['captchaResponse']))
            throw new Error('MISSING_DATA', 'captchaResponse', 400);
        
        if(!$this -> users -> validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        if(!$this -> validateCaptchaChal($body['captchaChallenge']))
            throw new Error('VALIDATION_ERROR', 'captchaChallenge', 400);
        if(!$this -> validateCaptchaResp($body['captchaResponse']))
            throw new Error('VALIDATION_ERROR', 'captchaResponse', 400);
            
        $email = strtolower($body['email']);
        $captchaReference = md5(CAPTCHA_SALT.strtolower($body['captchaResponse']).$email);
        if($captchaReference != $body['captchaChallenge'])
            throw new Error('INVALID_CAPTCHA', 'Invalid captcha code', 400);
        
        $this -> users -> createUser([
            'email' => $body['email'],
            'password' => @$body['password'],
            'refid' => @$body['refid']
        ]);
    }
    
    public function getCaptcha($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        if(!isset($query['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        
        if(!$this -> users -> validateEmail($query['email']))
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
    
    public function verify($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        $user = $this -> users -> getUser([
            'email' => @$body['email']
        ]);
        
        $this -> vc -> useCode($user['uid'], 'REGISTER_USER', @$body['code']);
        
        $this -> users -> verifyUser([
            'uid' => $user['uid']
        ]);
    }
    
    private function validateCaptchaChal($captcha) {
        return preg_match('/^[a-f0-9]{32}$/', $captcha);
    }

    private function validateCaptchaResp($captcha) {
        return preg_match('/^[a-np-zA-NP-Z1-9]{4}$/', $captcha);
    }
}

?>