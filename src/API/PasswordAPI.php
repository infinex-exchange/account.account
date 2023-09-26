<?php

require_once __DIR__.'/validate.php';

use Infinex\Exceptions\Error;

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
        $rc -> delete('/password', [$this, 'resetPassword']);
        $rc -> patch('/password', [$this, 'confirmResetPassword']);
    }
    
    public function changePassword($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!isset($body['oldPassword']))
            throw new Error('MISSING_DATA', 'oldPassword', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        
        if(!validatePassword($body['oldPassword']))
            throw new Error('VALIDATION_ERROR', 'old_password', 400);
        if(!validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
        
        $task = array(
            ':uid' => $auth['uid']
        );
    
        $sql = 'SELECT password
                FROM users
                WHERE uid = :uid';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
    
        if(! $row || !password_verify($body['oldPassword'], $row['password']))
            throw new Error('INVALID_PASSWORD', 'Incorrect old password', 401);
            
        if($body['oldPassword'] == $body['password'])
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
    
    public function resetPassword($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        
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
                'uid' => $uid,
                'template' => 'password_reset',
                'context' => [
                    'code' => $generatedCode
                ],
                'email' => $email
            ]
        );
    }
    
    public function confirmResetPassword($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        if(!isset($body['code']))
            throw new Error('MISSING_DATA', 'code', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        if(!validateVeriCode($body['code']))
            throw new Error('VALIDATION_ERROR', 'code', 400);
        if(!validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
        
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
            throw new Error('INVALID_VERIFICATION_CODE', 'Invalid verification code', 401);
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