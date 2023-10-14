<?php

use Infinex\Exceptions\Error;
use foroco\BrowserDetection;

class SessionsAPI {
    private $log;
    private $amqp;
    private $sessions;
    private $users;
    
    function __construct($log, $amqp, $sessions, $users) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> sessions = $sessions;
        $this -> users = $users;

        $this -> log -> debug('Initialized sessions/api keys API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/sessions', [$this, 'getAllSessions']);
        $rc -> get('/sessions/{sid}', [$this, 'getSession']);
        $rc -> delete('/sessions/{sid}', [$this, 'killSession']);
        $rc -> post('/sessions', [$this, 'login']);
        $rc -> get('/api-keys', [$this, 'getAllApiKeys']);
        $rc -> get('/api-keys/{keyid}', [$this, 'getApiKey']);
        $rc -> patch('/api-keys/{keyid}', [$this, 'editApiKey']);
        $rc -> delete('/api-keys/{keyid}', [$this, 'deleteApiKey']);
        $rc -> post('/api-keys', [$this, 'addApiKey']);
    }
    
    public function getAllSessions($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
            
        $resp = $this -> sessions -> getSessions([
            'uid' => $auth['uid'],
            'origin' => 'WEBAPP',
            'offset' => @$body['offset'],
            'limit' => @$body['limit']
        ]);
        
        foreach($resp['sessions'] as $k => $v)
            $resp['sessions'][$k] = $this -> ptpSession($v, $auth['sid']);
        
        return $resp;
    }
    
    public function getSession($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        return $this -> ptpSession(
            $this -> sessions -> getSession([
                'uid' => $auth['uid'],
                'sid' => $path['sid'],
                'origin' => 'WEBAPP'
            ]),
            $auth['sid']
        );
    }
    
    public function killSession($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        $this -> sessions -> killSession([
            'uid' => $auth['uid'],
            'sid' => $path['sid'],
            'origin' => 'WEBAPP'
        ]);
    }
    
    public function login($path, $query, $body, $auth, $ua) {
        $th = $this;
        
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        try {
            $uid = $this -> users -> emailToUid([
                'email' => @$body['email']
            ]);
            
            $user = $this -> users -> getUser([
                'uid' => $uid
            ]);
        
            $this -> users -> checkPassword([
                'uid' => $uid,
                'password' => @$body['password']
            ]);
        }
        catch(Error $e) {
            if($e -> getCode() == 400) // rethrow all missing data and validation errors
                throw $e;
            throw new Error('LOGIN_FAILED', 'Incorrect username or password', 401);
        }
        
        if(!$user['verified'])
            throw new Error(
                'ACCOUNT_INACTIVE',
                'Your account is inactive. Please check your mailbox for activation link',
                403
            );
        
        return $this -> amqp -> call(
            'account.mfa',
            'mfa',
            [
                'uid' => $uid,
                'case' => 'login',
                'action' => 'login',
                'context' => null,
                'code' => @$body['code2FA']
            ]
        ) -> then(function() use($th, $ua, $uid, $body) {
            $browserDetection = new BrowserDetection();
            $browser = $browserDetection -> getAll($ua);
            
            $session = $th -> sessions -> createSession([
                'uid' => $uid,
                'origin' => 'WEBAPP',
                'browser' => $browser['browser_title'],
                'os' => $browser['os_title'],
                'device' => $browser['device_type'],
                'remember' => @$body['remember']
            ]);
            
            return [
                'apiKey' => $session['apiKey']
            ];
        });
    }
    
    public function getAllApiKeys($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
            
        $resp = $this -> sessions -> getSessions([
            'uid' => $auth['uid'],
            'origin' => 'API',
            'offset' => @$body['offset'],
            'limit' => @$body['limit']
        ]);
        
        $apiKeys = [];
        foreach($resp['sessions'] as $k => $v)
            $apiKeys[$k] = $this -> ptpApiKey($v);
        
        return [
            'apiKeys' => $apiKeys,
            'more' => $resp['more']
        ];
    }
    
    public function getApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        return $this -> ptpApiKey(
            $this -> sessions -> getSession([
                'uid' => $auth['uid'],
                'sid' => $path['keyid'],
                'origin' => 'API'
            ])
        );
    }
    
    public function editApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $this -> sessions -> editSession([
            'uid' => $auth['uid'],
            'sid' => $path['keyid'],
            'description' => @$body['description']
        ]);
    }
    
    public function deleteApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $this -> sessions -> killSession([
            'uid' => $auth['uid'],
            'sid' => $path['keyid'],
            'origin' => 'API'
        ]);
    }
    
    public function addApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $resp = $this -> sessions -> createSession([
            'uid' => $auth['uid'],
            'origin' => 'API',
            'description' => @$body['description']
        ]);
        
        return [
            'keyid' => $resp['sid'],
            'apiKey' => $resp['apiKey']
        ];
    }
    
    private function ptpSession($record, $currentSid) {
        return [
            'sid' => $record['sid'],
            'lastAct' => $record['lastAct'],
            'browser' => $record['browser'],
            'os' => $record['os'],
            'device' => $record['device'],
            'current' => ($record['sid'] == $currentSid)
        ]; 
    }
    
    private function ptpApiKey($record) {
        return [
            'keyid' => $record['sid'],
            'apiKey' => $record['apiKey'],
            'description' => $record['description'],
            'lastAct' => $record['lastAct']
        ];
    }
}

?>