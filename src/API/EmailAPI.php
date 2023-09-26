<?php

require_once __DIR__.'/validate.php';

use Infinex\Exceptions\Error;

class EmailAPI {
    private $log;
    private $amqp;
    private $pdo;
    private $rest;
    
    function __construct($log, $amqp, $pdo, $rest) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> rest = $rest;
        
        $this -> rest -> get('/email', [$this, 'getEmail']);
        $this -> rest -> put('/email', [$this, 'changeEmail']);
        $this -> rest -> patch('/email', [$this, 'confirmChangeEmail']);
        $this -> rest -> delete('/email', [$this, 'cancelChangeEmail']);
        
        $this -> log -> debug('Initialized email API');
    }
    
    public function getEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = 'SELECT email
                FROM users
                WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        $currentEmail = $row['email'];
        
        $sql = "SELECT context_data
                FROM email_codes
                WHERE uid = :uid
                AND context = 'CHANGE_EMAIL'";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        $pendingEmail = null;
        
        if($row)
            $pendingEmail = $row['context_data'];
        
        return [
            'email' => $currentEmail,
            'pendingChange' => $pendingEmail
        ];
    }
    
    public function changeEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        
        if(!validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        
        $email = strtolower($body['email']);
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = 'SELECT email,
                       password
                FROM users
                WHERE uid = :uid';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(! $row || !password_verify($body['password'], $row['password']))
            throw new Error('INVALID_PASSWORD', 'Incorrect password', 401);
        
        if($email == $row['email'])
            throw new Error('NOTHING_CHANGED', 'New e-mail is the same as old e-mail', 400);
        $oldEmail = $row['email'];
        
        $task = array(
            ':email' => $email
        );
        
        $sql = 'SELECT 1
                FROM users
                WHERE email = :email';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($row)
            throw new Error('ALREADY_EXISTS', 'This e-mail address is already in use', 409);
        
        $this -> pdo -> beginTransaction();
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = "DELETE FROM email_codes
                WHERE uid = :uid
                AND context = 'CHANGE_EMAIL'";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $generatedCode = sprintf('%06d', rand(0, 999999));
        
        $task = array(
            ':uid' => $auth['uid'],
            ':code' => $generatedCode,
            ':context_data' => $email
        );
        
        $sql = "INSERT INTO email_codes (
            uid,
            context,
            code,
            context_data
        )
        VALUES (
            :uid,
            'CHANGE_EMAIL',
            :code,
            :context_data
        )";
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
    
        $this -> amqp -> pub(
            'mail',
            [
                'uid' => $auth['uid'],
                'template' => 'change_email',
                'context' => [
                    'new_email' => $email,
                    'code' => $generatedCode
                ],
                'email' => $oldEmail
            ]
        );
    }
    
    public function confirmChangeEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!isset($body['code']))
            throw new Error('MISSING_DATA', 'code', 400);
        
        if(!validateVeriCode($body['code']))
            throw new Error('VALIDATION_ERROR', 'code', 400);
        
        $this -> pdo -> beginTransaction();
    
        $task = array(
            ':uid' => $auth['uid'],
            ':code' => $body['code']
        );
        
        $sql = "DELETE FROM email_codes
                WHERE uid = :uid
                AND context = 'CHANGE_EMAIL'
                AND code = :code
                RETURNING context_data";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row) {
            $this -> pdo -> rollBack();
            throw new Error('INVALID_VERIFICATION_CODE', 'Invalid verification code', 401);
        }
        $newEmail = $row['context_data'];
        
        $task = array(
            ':email' => $newEmail
        );
        
        $sql = 'SELECT 1
                FROM users
                WHERE email = :email
                FOR UPDATE';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($row) {
            $this -> pdo -> rollBack();
            throw new Error('ALREADY_EXISTS', 'This e-mail address is already in use', 409);
        }
        
        $task = array(
            ':uid' => $auth['uid'],
            ':email' => $newEmail
        );
    
        $sql = 'UPDATE users
                SET email = :email
                WHERE uid = :uid';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
    }
    
    public function cancelChangeEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = "DELETE FROM email_codes
                WHERE uid = :uid
                AND context = 'CHANGE_EMAIL'
                RETURNING 1";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'No pending e-mail change', 404);
    }
}

?>