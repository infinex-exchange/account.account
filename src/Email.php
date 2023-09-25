<?php

require_once __DIR__.'/validate.php';

use Infinex\API\APIException;

class EmailAPI {
    private $log;
    private $amqp;
    private $pdo;
    
    function __construct($log, $amqp, $pdo) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized email API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/email', [$this, 'getEmail']);
        $this -> log -> debug('Registered route GET /email');
        
        $rc -> put('/email', [$this, 'changeEmail']);
        $this -> log -> debug('Registered route PUT /email');
        
        $rc -> patch('/email', [$this, 'confirmChangeEmail']);
        $this -> log -> debug('Registered route PATCH /email');
        
        $rc -> delete('/email', [$this, 'cancelChangeEmail']);
        $this -> log -> debug('Registered route DELETE /email');
    }
    
    public function getEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
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
            'pending_change' => $pendingEmail
        ];
    }
    
    public function changeEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!isset($body['old_password']))
            throw new APIException(400, 'MISSING_DATA', 'old_password');
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        
        if(!validatePassword($body['old_password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'old_password');
        if(!validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        
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
        
        if(! $row || !password_verify($body['old_password'], $row['password']))
            throw new APIException(401, 'INVALID_PASSWORD', 'Incorrect old password');
        
        if($email == $row['email'])
            throw new APIException(400, 'NOTHING_CHANGED', 'New e-mail is the same as old e-mail');
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
            throw new APIException(409, 'ALREADY_EXISTS', 'This e-mail address is already in use');
        
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
                'email' => $oldEmail,
                'template' => 'change_email',
                'context' => [
                    'new_email' => $email,
                    'code' => $generatedCode
                ]
            ]
        );
    }
    
    public function confirmChangeEmail($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!isset($body['code']))
            throw new APIException(400, 'MISSING_DATA', 'code');
        
        if(!validateVeriCode($body['code']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code');
        
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
            throw new APIException(401, 'INVALID_VERIFICATION_CODE', 'Invalid verification code');
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
            throw new APIException(409, 'ALREADY_EXISTS', 'This e-mail address is already in use');
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
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
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
            throw new APIException(404, 'NOT_FOUND', 'No pending e-mail change');
    }
}

?>