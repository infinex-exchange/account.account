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
            'offset' => @$query['offset'],
            'limit' => @$query['limit']
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
        
        $session = $this -> sessions -> getSession([
            'sid' => $path['sid']
        ]);
        
        if($session['origin'] != 'WEBAPP')
            throw new Error('NOT_FOUND', 'Session '.$path['sid'].' not found', 404);
        
        if($session['uid'] != $auth['uid'])
            throw new Error('FORBIDDEN', 'No permissions to session '.$path['sid'], 403);
        
        return $this -> ptpSession(
            $session,
            $auth['sid']
        );
    }
    
    public function killSession($path, $query, $body, $auth) {
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        $session = $this -> sessions -> getSession([
            'sid' => $path['sid']
        ]);
        
        if($session['origin'] != 'WEBAPP')
            throw new Error('NOT_FOUND', 'Session '.$path['sid'].' not found', 404);
        
        if($session['uid'] != $auth['uid'])
            throw new Error('FORBIDDEN', 'No permissions to session '.$path['sid'], 403);
        
        $this -> sessions -> killSession([
            'sid' => $path['sid']
        ]);
    }
    
    public function login($path, $query, $body, $auth, $ua) {
        $th = $this;
        
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        try {
            $user = $this -> users -> getUser([
                'email' => @$body['email']
            ]);
        
            $this -> users -> checkPassword([
                'uid' => $user['uid'],
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
                'uid' => $user['uid'],
                'case' => 'LOGIN',
                'action' => 'login',
                'context' => null,
                'code' => @$body['code2FA']
            ]
        ) -> then(function() use($th, $ua, $user, $body) {
            $browserDetection = new BrowserDetection();
            $browser = $browserDetection -> getAll($ua);
            
            $session = $th -> sessions -> createSession([
                'uid' => $user['uid'],
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
            'offset' => @$query['offset'],
            'limit' => @$query['limit']
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
        
        $session = $this -> sessions -> getSession([
            'sid' => $path['keyid']
        ]);
        
        if($session['origin'] != 'API')
            throw new Error('NOT_FOUND', 'API key '.$path['keyid'].' not found', 404);
        
        if($session['uid'] != $auth['uid'])
            throw new Error('FORBIDDEN', 'No permissions to API key '.$path['keyid'], 403);
        
        return $this -> ptpApiKey($session);
    }
    
    public function editApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $session = $this -> sessions -> getSession([
            'sid' => $path['keyid']
        ]);
        
        if($session['origin'] != 'API')
            throw new Error('NOT_FOUND', 'API key '.$path['keyid'].' not found', 404);
        
        if($session['uid'] != $auth['uid'])
            throw new Error('FORBIDDEN', 'No permissions to API key '.$path['keyid'], 403);
        
        $this -> sessions -> editSession([
            'sid' => $path['keyid'],
            'description' => @$body['description']
        ]);
        
        return $this -> ptpSession(
            $this -> sessions -> getSession([
                'sid' => $path['keyid']
            ])
        );
    }
    
    public function deleteApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $session = $this -> sessions -> getSession([
            'sid' => $path['keyid']
        ]);
        
        if($session['origin'] != 'API')
            throw new Error('NOT_FOUND', 'API key '.$path['keyid'].' not found', 404);
        
        if($session['uid'] != $auth['uid'])
            throw new Error('FORBIDDEN', 'No permissions to API key '.$path['keyid'], 403);
        
        $this -> sessions -> killSession([
            'sid' => $path['keyid']
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
        
        return ptpApiKey(
            $this -> sessions -> getSession([
                'sid' => $resp['sid']
            ])
        );
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