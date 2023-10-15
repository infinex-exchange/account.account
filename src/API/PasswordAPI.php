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
        
        $uid = $this -> users -> emailToUid([
            'email' => $body['email']
        ]);
        
        $generatedCode = $this -> vc -> createCode(
            $uid,
            'PASSWORD_RESET'
        );
        
        $this -> amqp -> pub(
            'mail',
            [
                'uid' => $uid,
                'template' => 'password_reset',
                'context' => [
                    'code' => $generatedCode
                ],
                'email' => strtolower($body['email'])
            ]
        );
    }
    
    public function confirmResetPassword($path, $query, $body, $auth) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        $uid = $this -> users -> emailToUid([
            'email' => $body['email']
        ]);
        
        $this -> vc -> useCode(
            $uid,
            'PASSWORD_RESET',
            @$body['code']
        );
        
        $this -> users -> changePassword([
            'uid' => $uid,
            'password' => @$body['password']
        ]);
    }
}

?>