<?php

require __DIR__.'/validate.php';

use Infinex\API\APIException;
use foroco\BrowserDetection;

class AuthApiV2 {
    private $log;
    private $pdo;
    private $mfa;
    
    function __construct($log, $pdo, $mfa) {
        $this -> log = $log;
        $this -> pdo = $pdo;
        $this -> mfa = $mfa;
        
        $this -> log -> debug('Initialized auth API V2');
    }
    
    public function initRoutes($rc) {
        $rc -> post('/login', [$this, 'login']);
        $this -> log -> debug('Registered route POST /login');
        
        //
    }
    
    public function login($path, $query, $body, $auth, $ua) {
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        if(!isset($body['password']))
            throw new APIException(400, 'MISSING_DATA', 'password');
        
        if(!$this -> validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        if(!$this -> validatePassword($body['password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'password');
        if(isset($body['remember']) && !is_bool($body['remember']))
            throw new APIException(400, 'VALIDATION_ERROR', 'remember');
        if(isset($body['code_2fa']) && !$this -> validate2FA($body['code_2fa']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code_2fa');
        
        $email = strtolower($body['email']);
        
        $task = array(
            ':email' => $email
        );
    
        $sql = 'SELECT uid,
                       password,
                       verified
                FROM users
                WHERE email = :email';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(! $row || !password_verify($body['password'], $row['password']))
            throw new APIException(401, 'LOGIN_FAILED', 'Incorrect e-mail or password');
        
        if(! $row['verified'])
            throw new APIException(401, 'ACCOUNT_INACTIVE', 'Your account is inactive. Please check your mailbox for activation link');
        
        if(isset($body['code_2fa'])) {
            if(! $this -> mfa -> response($row['uid'], 'login', null, $body['code_2fa']))
                throw new APIException(401, 'INVALID_2FA', 'Invalid 2FA code');
        }
        else {
            $prov = $this -> mfa -> challenge($row['uid'], 'login', 'login', null);
            if($prov != null)
                return [
                    'api_key' => null,
                    'mfa_provider' => $prov
                ];
        }
    
        $generatedApiKey = bin2hex(random_bytes(32));
        
        $browserDetection = new BrowserDetection();
        $browser = $browserDetection -> getAll($ua);
        
        $task = array(
            ':uid' => $row['uid'],
            ':api_key' => $generatedApiKey,
            ':wa_remember' => $body['remember'] ? 1 : 0,
            ':wa_browser' => $browser['browser_title'],
            ':wa_os' => $browser['os_title'],
            ':wa_device' => $browser['device_type']
        );
        
        $sql = "INSERT INTO sessions (
            uid,
            api_key,
            origin,
            wa_remember,
            wa_lastact,
            wa_browser,
            wa_os,
            wa_device
        )
        VALUES (
            :uid,
            :api_key,
            'WEBAPP',
            :wa_remember,
            CURRENT_TIMESTAMP,
            :wa_browser,
            :wa_os,
            :wa_device
        )";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        return [
            'api_key' => $generatedApiKey,
            'mfa_provider' => null
        ];
    }
}

?>