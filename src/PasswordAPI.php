<?php

require_once __DIR__.'/validate.php';

use Infinex\API\APIException;

class PasswordAPI {
    private $log;
    private $amqp;
    private $pdo;
    
    function __construct($log, $amqp, $pdo) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized password API');
    }
    
    public function initRoutes($rc) {
        $rc -> put('/password', [$this, 'changePassword']);
        $this -> log -> debug('Registered route PUT /password');
        
        $rc -> delete('/password', [$this, 'resetPassword']);
        $this -> log -> debug('Registered route DELETE /password');
        
        $rc -> patch('/password', [$this, 'confirmResetPassword']);
        $this -> log -> debug('Registered route PATCH /password');
    }
    
    public function changePassword($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!isset($body['old_password']))
            throw new APIException(400, 'MISSING_DATA', 'old_password');
        if(!isset($body['password']))
            throw new APIException(400, 'MISSING_DATA', 'password');
        
        if(!validatePassword($body['old_password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'old_password');
        if(!validatePassword($body['password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'password');
        
        $task = array(
            ':uid' => $auth['uid']
        );
    
        $sql = 'SELECT password
                FROM users
                WHERE uid = :uid';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
    
        if(! $row || !password_verify($body['old_password'], $row['password']))
            throw new APIException(401, 'INVALID_PASSWORD', 'Incorrect old password');
            
        if($jreq['old_password'] == $jreq['password'])
            return;
    
        $hashedPassword = password_hash($body['password'], PASSWORD_DEFAULT);
    
        $task = array(
            ':uid' => $auth['uid'],
            ':password' => $hashedPassword
        );
    
        $sql = 'UPDATE users
                SET password = :password
                WHERE uid = :uid';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
    }
    
    public function resetPassword($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Already logged in');
        
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        
        if(!$this -> validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        
        $email = strtolower($body['email']);
        
        $task = array(
            ':email' => $email
        );
        
        $sql = 'SELECT uid
                FROM users
                WHERE email = :email';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(! $row)
            return;
        
        $uid = $row['uid'];
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
            'PASSWORD_RESET',
            :code
        )";
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> amqp -> pub(
            'mail',
            [
                'email' => $email,
                'template' => 'password_reset',
                'context' => [
                    'code' => $generatedCode
                ]
            ]
        );
    }
    
    public function confirmResetPassword($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Already logged in');
        
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        if(!isset($body['code']))
            throw new APIException(400, 'MISSING_DATA', 'code');
        if(!isset($body['password']))
            throw new APIException(400, 'MISSING_DATA', 'password');
        
        if(!$this -> validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        if(!$this -> validateVeriCode($body['code']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code');
        if(!$this -> validatePassword($body['password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'password');
        
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
            AND email_codes.context = 'PASSWORD_RESET'
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
        
        $hashedPassword = password_hash($body['password'], PASSWORD_DEFAULT);
        
        $task = array(
            ':uid' => $uid,
            ':password' => $hashedPassword
        );
        
        $sql = 'UPDATE users
            SET password = :password
            WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
    }
}

?>