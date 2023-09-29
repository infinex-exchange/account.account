<?php

require_once __DIR__.'/validate.php';

use Infinex\Exceptions\Error;
use Infinex\Pagination;
use foroco\BrowserDetection;

class SessionsAPI {
    private $log;
    private $pdo;
    private $mfa;
    
    function __construct($log, $pdo, $mfa) {
        $this -> log = $log;
        $this -> pdo = $pdo;
        $this -> mfa = $mfa;

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
            
        $pag = new Pagination\Offset(50, 500, $query);
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = "SELECT sid,
                       wa_remember,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact,
                       wa_browser,
                       wa_os,
                       wa_device
               FROM sessions
               WHERE uid = :uid
               AND origin = 'WEBAPP'
               ORDER BY sid DESC"
             . $pag -> sql();
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $sessions = [];
        
        while($row = $q -> fetch()) {
            if($pag -> iter()) break;
            
            $sessions[] = [
                'sid' => $row['sid'],
                'lastAct' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null,
                'browser' => $row['wa_browser'],
                'os' => $row['wa_os'],
                'device' => $row['wa_device'],
                'current' => ($auth['sid'] == $row['sid']) 
            ];
        }
        
        return [
            'sessions' => $sessions,
            'more' => $pag -> more
        ];
    }
    
    public function login($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new Error('ALREADY_LOGGED_IN', 'Already logged in', 403);
        
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        if(!validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
        if(isset($body['remember']) && !is_bool($body['remember']))
            throw new Error('VALIDATION_ERROR', 'remember', 400);
        
        $email = strtolower($body['email']);
        $remember = isset($body['remember']) ? $body['remember'] : false;
        
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
            throw new Error('LOGIN_FAILED', 'Incorrect e-mail or password', 401);
        
        if(! $row['verified'])
            throw new Error('ACCOUNT_INACTIVE', 'Your account is inactive. Please check your mailbox for activation link', 401);
        
        $this -> mfa -> mfa(
            $auth['uid'],
            'login',
            'login',
            null,
            isset($body['code2FA']) ? $body['code2FA'] : null
        );
    
        $generatedApiKey = bin2hex(random_bytes(32));
        
        $browserDetection = new BrowserDetection();
        $browser = $browserDetection -> getAll($ua);
        
        $task = array(
            ':uid' => $row['uid'],
            ':api_key' => $generatedApiKey,
            ':wa_remember' => $remember ? 1 : 0,
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
            'apiKey' => $generatedApiKey
        ];
    }
    
    public function getSession($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        if(!$this -> validateSid($path['sid']))
            throw new Error('VALIDATION_ERROR', 'sid', 400);
        
        $task = array(
            ':uid' => $auth['uid'],
            ':sid' => $path['sid']
        );
        
        $sql = "SELECT wa_remember,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact,
                       wa_browser,
                       wa_os,
                       wa_device
               FROM sessions
               WHERE uid = :uid
               AND sid = :sid
               AND origin = 'WEBAPP'";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'Session '.$path['sid'].' not found', 404);
        
        return [
            'sid' => $path['sid'],
            'lastAct' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null,
            'browser' => $row['wa_browser'],
            'os' => $row['wa_os'],
            'device' => $row['wa_device'],
            'current' => ($auth['sid'] == $path['sid'])
        ];
    }
    
    public function killSession($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        if(!$this -> validateSid($path['sid']))
            throw new Error('VALIDATION_ERROR', 'sid', 400);
        
        $task = array(
            ':uid' => $auth['uid'],
            ':sid' => $path['sid']
        );
        
        $sql = "DELETE FROM sessions
                WHERE uid = :uid
                AND sid = :sid
                AND origin = 'WEBAPP'
                RETURNING 1";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'Session '.$path['sid'].' not found', 404);
    }
    
    public function getAllApiKeys($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        $pag = new Pagination\Offset(50, 500, $query);
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = "SELECT sid,
                       api_key,
                       ak_description,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact
               FROM sessions
               WHERE uid = :uid
               AND origin = 'API'
               ORDER BY sid ASC"
             . $pag -> sql();
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $apiKeys = [];
        
        while($row = $q -> fetch()) {
            if($pag -> iter()) break;
            
            $apiKeys[] = [
                'keyid' => $row['sid'],
                'apiKey' => $row['api_key'],
                'description' => $row['ak_description'],
                'lastAct' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null
            ];
        }
        
        return [
            'apiKeys' => $apiKeys,
            'more' => $pag -> more
        ];
    }
    
    public function getApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!$this -> validateSid($path['keyid']))
            throw new Error('VALIDATION_ERROR', 'keyid', 400);
        
        $task = array(
            ':uid' => $auth['uid'],
            ':sid' => $path['keyid']
        );
        
        $sql = "SELECT api_key,
                       ak_description,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact
               FROM sessions
               WHERE uid = :uid
               AND sid = :sid
               AND origin = 'API'";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'API key '.$path['keyid'].' not found', 404);
        
        return [
             'keyid' => $path['keyid'],
             'apiKey' => $row['api_key'],
             'description' => $row['ak_description'],
             'lastAct' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null
        ];
    }
    
    public function deleteApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!$this -> validateSid($path['keyid']))
            throw new Error('VALIDATION_ERROR', 'keyid', 400);
        
        $task = array(
            ':uid' => $auth['uid'],
            ':sid' => $path['keyid']
        );
        
        $sql = "DELETE FROM sessions
                WHERE uid = :uid
                AND sid = :sid
                AND origin = 'API'
                RETURNING 1";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'API key '.$path['keyid'].' not found', 404);
    }
    
    public function addApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!isset($body['description']))
            throw new Error('MISSING_DATA', 'description', 400);
        
        if(!$this -> validateApiKeyDescription($body['description']))
            throw new Error('VALIDATION_ERROR', 'description', 400);
    
        // Check api key with this name already exists
        $task = array(
            ':uid' => $auth['uid'],
            ':description' => $body['description']
        );
        
        $sql = "SELECT sid
                FROM sessions
                WHERE uid = :uid
                AND ak_description = :description
                AND origin = 'API'";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($row)
            throw new Error('ALREADY_EXISTS', 'API key with this name already exists', 409);
        
        // Generate and insert api key
        $generatedApiKey = bin2hex(random_bytes(32));
        
        $task = array(
            ':uid' => $auth['uid'],
            ':api_key' => $generatedApiKey,
            ':description' => $body['description']
        );
        
        $sql = "INSERT INTO sessions(
                    uid,
                    api_key,
                    origin,
                    ak_description
                ) VALUES (
                    :uid,
                    :api_key,
                    'API',
                    :description
                )
                RETURNING sid";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        return [
            'keyid' => $row['sid'],
            'apiKey' => $generatedApiKey
        ];
    }
    
    public function editApiKey($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!isset($body['description']))
            throw new Error('MISSING_DATA', 'description', 400);
        
        if(!$this -> validateSid($path['keyid']))
            throw new Error('VALIDATION_ERROR', 'keyid', 400);
        if(!$this -> validateApiKeyDescription($body['description']))
            throw new Error('VALIDATION_ERROR', 'description', 400);
    
        // Check api key with this name already exists
        $task = array(
            ':uid' => $auth['uid'],
            ':description' => $body['description']
        );
        
        $sql = "SELECT sid
                FROM sessions
                WHERE uid = :uid
                AND ak_description = :description
                AND origin = 'API'";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($row) {
            if($row['sid'] == $path['keyid'])
                return;
            throw new Error('ALREADY_EXISTS', 'API key with this name already exists', 409);
        }
        
        // Update api key
        $task = array(
            ':uid' => $auth['uid'],
            ':sid' => $path['keyid'],
            ':description' => $body['description']
        );
        
        $sql = "UPDATE sessions
                SET ak_description = :description
                WHERE uid = :uid
                AND sid = :sid
                AND origin = 'API'
                RETURNING 1";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'API key '.$path['keyid'].' not found', 404);
    }
    
    private function validateSid($sid) {
        if(!is_int($sid)) return false;
        if($sid < 1) return false;
        return true;
    }
    
    private function validateApiKeyDescription($desc) {
        return preg_match('/^[a-zA-Z0-9 ]{1,255}$/', $desc);
    }
}

?>