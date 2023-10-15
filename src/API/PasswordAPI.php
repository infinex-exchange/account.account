<?php

use Infinex\Exceptions\Error;

class PasswordAPI {
    private $log;
    private $amqp;
    private $users;
    private $vc;
    
    function __construct($log, $amqp, $users, $vc) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> users = $users;
        $this -> vc = $vc;
        
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
        
        $this -> users -> checkPassword([
            'uid' => $auth['uid'],
            'password' => @$body['oldPassword']
        ]);
        
        $this -> users -> changePassword([
            'uid' => $auth['uid'],
            'password' => @$body['password']
        ]);
    }
    
    public function resetPassword($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        $user = $this -> users -> getUser([
            'email' => @$body['email']
        ]);
        
        if(!$user['verified'])
            throw new Error(
                'ACCOUNT_INACTIVE',
                'Your account is inactive. Please check your mailbox for activation link',
                403
            );
        
        $generatedCode = $this -> vc -> createCode(
            $user['uid'],
            'PASSWORD_RESET'
        );
        
        $this -> amqp -> pub(
            'mail',
            [
                'uid' => $user['uid'],
                'template' => 'password_reset',
                'context' => [
                    'code' => $generatedCode
                ],
                'email' => $user['email']
            ]
        );
    }
    
    public function confirmResetPassword($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        $user = $this -> users -> getUser([
            'email' => @$body['email']
        ]);
        
        $this -> vc -> useCode(
            $user['uid'],
            'PASSWORD_RESET',
            @$body['code']
        );
        
        $this -> users -> changePassword([
            'uid' => $user['uid'],
            'password' => @$body['password']
        ]);
    }
}

?>