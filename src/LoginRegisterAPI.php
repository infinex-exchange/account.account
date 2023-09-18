<?php

require __DIR__.'/validate.php';

use Infinex\API\APIException;
use foroco\BrowserDetection;
use Gregwar\Captcha\CaptchaBuilder;

class LoginRegisterAPI {
    private $log;
    private $amqp;
    private $pdo;
    private $mfa;
    
    function __construct($log, $amqp, $pdo, $mfa) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> mfa = $mfa;
        
        $this -> log -> debug('Initialized login/register API');
    }
    
    public function initRoutes($rc) {
        $rc -> post('/login', [$this, 'login']);
        $this -> log -> debug('Registered route POST /login');
        
        $rc -> post('/register', [$this, 'register']);
        $this -> log -> debug('Registered route POST /register');
        
        $rc -> get('/register/captcha', [$this, 'getCaptcha']);
        $this -> log -> debug('Registered route GET /register/captcha');
        
        $rc -> post('/register/verify', [$this, 'verify']);
        $this -> log -> debug('Registered route POST /register/verify');
    }
    
    public function login($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Already logged in');
        
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
    
    public function register($path, $query, $body, $auth) {
        if($auth)
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Cannot register a new account while logged in');
        
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        if(!isset($body['password']))
            throw new APIException(400, 'MISSING_DATA', 'password');
        if(!isset($body['captcha_challenge']))
            throw new APIException(400, 'MISSING_DATA', 'captcha_challenge');
        if(!isset($body['captcha_response']))
            throw new APIException(400, 'MISSING_DATA', 'captcha_response');
        
        if(!validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        if(!validatePassword($body['password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'password');
        if(!validateCaptchaChal($body['captcha_challenge']))
            throw new APIException(400, 'VALIDATION_ERROR', 'captcha_challenge');
        if(!validateCaptchaResp($body['captcha_response']))
            throw new APIException(400, 'VALIDATION_ERROR', 'captcha_response');
        if(isset($body['refid']) && !validateUintNz($body['refid']))
            throw new APIException(400, 'VALIDATION_ERROR', 'refid');
        
        $email = strtolower($body['email']);
        
        $captchaReference = md5(CAPTCHA_SALT.strtolower($body['captcha_response']).$email);
        if($captchaReference != $body['captcha_challenge'])
            throw new APIException(400, 'INVALID_CAPTCHA', 'Invalid captcha code');
        
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
            throw new APIException(400, 'EMAIL_ALREADY_USED', 'There is already an account registered with this email address.');
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
        
        // TODO: Remove in the future. Create wallets for all assets
        $task = array(
            ':uid' => $uid
        );
        
        $sql = 'INSERT INTO wallet_balances (
            uid,
            assetid,
            total,
            locked
        )
        SELECT :uid,
               assetid,
               0,
               0
        FROM assets';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        // Reflink
        if(isset($body['refid'])) {
            $task = array(
                ':refid' => $body['refid']
            );
            
            $sql = 'SELECT uid,
                           active
                    FROM reflinks
                    WHERE refid = :refid';
            
            $q = $this -> pdo -> prepare($sql);
            $q -> execute($task);
            $row = $q -> fetch();
            
            if($row) {
                if($row['active']) {
                    $task = array(
                        ':refid' => $body['refid'],
                        ':slave_uid' => $uid
                    );
                    
                    $sql = 'INSERT INTO affiliations(
                                refid,
                                slave_uid,
                                slave_level
                            )
                            VALUES(
                                :refid,
                                :slave_uid,
                                1
                            )';
                    
                    $q = $this -> pdo -> prepare($sql);
                    $q -> execute($task);
                }
                
                $task = array(
                    ':slave_uid' => $uid,
                    ':master_uid' => $row['uid']
                );
                
                $sql = 'INSERT INTO affiliations(
                            refid,
                            slave_uid,
                            slave_level
                        )
                        SELECT affiliations.refid,
                               :slave_uid,
                               affiliations.slave_level + 1
                        FROM affiliations,
                             reflinks
                        WHERE affiliations.refid = reflinks.refid
                        AND affiliations.slave_level <= 3
                        AND affiliations.slave_uid = :master_uid
                        AND reflinks.active = TRUE';
            
                $q = $this -> pdo -> prepare($sql);
                $q -> execute($task);
            }
        }
        
        $this -> pdo -> commit();
        
        // Send verification email
        $this -> amqp -> pub(
            'mail',
            [
                'email' => $email,
                'template' => 'register_user',
                'context' => [
                    'code' => $generatedCode
                ]
            ]
        );
    }
    
    public function getCaptcha($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Already logged in');
        
        if(!isset($query['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        
        if(!$this -> validateEmail($query['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        
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
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Already logged in');
        
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        if(!isset($body['code']))
            throw new APIException(400, 'MISSING_DATA', 'code');
        
        if(!$this -> validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        if(!$this -> validateVeriCode($body['code']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code');
        
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
            throw new APIException(401, 'INVALID_VERIFICATION_CODE', 'Invalid verification code');
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
}

?>