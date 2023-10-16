<?php

use Infinex\Exceptions\Error;

class EmailAPI {
    private $log;
    private $amqp;
    private $pdo;
    private $users;
    private $vc;
    
    function __construct($log, $amqp, $pdo, $users, $vc) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> users = $users;
        $this -> vc = $vc;
        
        $this -> log -> debug('Initialized email API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/email', [$this, 'getEmail']);
        $rc -> put('/email', [$this, 'changeEmail']);
        $rc -> patch('/email', [$this, 'confirmChangeEmail']);
        $rc -> delete('/email', [$this, 'cancelChangeEmail']);
    }
    
    public function getEmail($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $user = $this -> users -> getUser([
            'uid' => $auth['uid']
        ]);
        
        $task = [
            ':uid' => $auth['uid']
        ];
        
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
            'email' => $user['email'],
            'pendingChange' => $pendingEmail
        ];
    }
    
    public function changeEmail($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        try {
            $this -> users -> getUser([
                'email' => @$body['email']
            ]);
            
            throw new Error('CONFLICT', 'This e-mail address is already in use', 409);
        }
        catch(Error $e) {
            if($e -> getStrCode() != 'NOT_FOUND')
                throw $e;
        }
        
        $email = strtolower($body['email']);
        
        $user = $this -> users -> getUser([
            'uid' => $auth['uid']
        ]);
        
        $this -> users -> checkPassword([
            'uid' => $auth['uid'],
            'password' => @$body['password']
        ]);
        
        $generatedCode = $this -> vc -> createCode(
            $auth['uid'],
            'CHANGE_EMAIL',
            $email
        );
    
        $this -> amqp -> pub(
            'mail',
            [
                'uid' => $auth['uid'],
                'template' => 'change_email',
                'context' => [
                    'new_email' => $email,
                    'code' => $generatedCode
                ],
                'email' => $user['email']
            ]
        );
        
        return [
            'email' => $user['email'],
            'pendingChange' => $email
        ];
    }
    
    public function confirmChangeEmail($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $newEmail = $this -> vc -> useCode(
            $auth['uid'],
            'CHANGE_EMAIL',
            @$body['code']
        );
        
        $this -> users -> changeEmail([
            'uid' => $auth['uid'],
            'email' => $newEmail
        ]);
        
        return [
            'email' => $newEmail,
            'pendingChange' => null
        ];
    }
    
    public function cancelChangeEmail($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(! $this -> vc -> deletePrevCodes($auth['uid'], 'CHANGE_EMAIL'))
            throw new Error('NOT_FOUND', 'No pending e-mail change', 404);
        
        $user = $this -> users -> getUser([
            'uid' => $auth['uid']
        ]);
        
        return [
            'email' => $user['email'],
            'pendingChange' => null
        ];
    }
}

?>