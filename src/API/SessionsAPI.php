<?php

require_once __DIR__.'/validate.php';

use Infinex\API\APIException;
use foroco\BrowserDetection;

class SessionsApiKeysAPI {
    private $log;
    private $amqp;
    private $pdo;
    private $mfa;
    
    function __construct($log, $amqp, $pdo, $mfa) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> mfa = $mfa;
        
        $this -> log -> debug('Initialized sessions/api keys API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/sessions', [$this, 'getAllSessions']);
        $this -> log -> debug('Registered route GET /sessions');
        
        $rc -> get('/sessions/{sid}', [$this, 'getSession']);
        $this -> log -> debug('Registered route GET /sessions/{sid}');
        
        $rc -> delete('/sessions/{sid}', [$this, 'killSession']);
        $this -> log -> debug('Registered route DELETE /sessions/{sid}');
        
        $rc -> post('/sessions', [$this, 'login']);
        $this -> log -> debug('Registered route POST /sessions');
        
        $rc -> get('/api_keys', [$this, 'getAllApiKeys']);
        $this -> log -> debug('Registered route GET /api_keys');
        
        $rc -> get('/api_keys/{keyid}', [$this, 'getApiKey']);
        $this -> log -> debug('Registered route GET /api_keys/{keyid}');
        
        $rc -> patch('/api_keys/{keyid}', [$this, 'editApiKey']);
        $this -> log -> debug('Registered route PATCH /api_keys/{keyid}');
        
        $rc -> delete('/api_keys/{keyid}', [$this, 'deleteApiKey']);
        $this -> log -> debug('Registered route DELETE /api_keys/{keyid}');
        
        $rc -> post('/api_keys', [$this, 'addApiKey']);
        $this -> log -> debug('Registered route POST /api_keys');
    }
    
    public function getAllSessions($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(isset($query['offset']) && !validateUint($query['offset']))
            throw new APIException(400, 'VALIDATION_ERROR', 'offset');
        
        $offset = isset($query['offset']) ? $query['offset'] : 0;
        
        $task = array(
            ':uid' => $auth['uid'],
            ':offset' => $offset
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
               ORDER BY sid DESC
               LIMIT 51
               OFFSET :offset";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $sessions = [];
        $more = false;
        
        while($row = $q -> fetch()) {
            if(count($sessions) == 50) {
                $more = true;
                break;
            }
            
            $sessions[] = [
                'sid' => $row['sid'],
                'lastact' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null,
                'browser' => $row['wa_browser'],
                'os' => $row['wa_os'],
                'device' => $row['wa_device'],
                'current_session' => ($auth['sid'] == $row['sid']) 
            ];
        }
        
        return [
            'sessions' => $sessions,
            'more' => $more
        ];
    }
    
    public function login($path, $query, $body, $auth, $ua) {
        if($auth)
            throw new APIException(403, 'ALREADY_LOGGED_IN', 'Already logged in');
        
        if(!isset($body['email']))
            throw new APIException(400, 'MISSING_DATA', 'email');
        if(!isset($body['password']))
            throw new APIException(400, 'MISSING_DATA', 'password');
        
        if(!validateEmail($body['email']))
            throw new APIException(400, 'VALIDATION_ERROR', 'email');
        if(!validatePassword($body['password']))
            throw new APIException(400, 'VALIDATION_ERROR', 'password');
        if(isset($body['remember']) && !is_bool($body['remember']))
            throw new APIException(400, 'VALIDATION_ERROR', 'remember');
        if(isset($body['code_2fa']) && !validate2FA($body['code_2fa']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code_2fa');
        
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
            throw new APIException(401, 'LOGIN_FAILED', 'Incorrect e-mail or password');
        
        if(! $row['verified'])
            throw new APIException(401, 'ACCOUNT_INACTIVE', 'Your account is inactive. Please check your mailbox for activation link');
        
        if(isset($body['code_2fa'])) {
            if(! $this -> mfa -> response($row['uid'], 'login', 'login', null, $body['code_2fa']))
                throw new APIException(401, 'INVALID_2FA', 'Invalid 2FA code');
        }
        else {
            $prov = $this -> mfa -> challenge($row['uid'], 'login', 'login', []);
            if($prov != null)
                throw new APIException(511, 'REQUIRE_2FA', $prov);
        }
    
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
            'api_key' => $generatedApiKey
        ];
    }
    
    public function getSession($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        if(!validateUintNz($path['sid']))
            throw new APIException(400, 'VALIDATION_ERROR', 'sid');
        
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
            throw new APIException(404, 'NOT_FOUND', 'Session '.$path['sid'].' not found');
        
        return [
            'sid' => $path['sid'],
            'lastact' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null,
            'browser' => $row['wa_browser'],
            'os' => $row['wa_os'],
            'device' => $row['wa_device'],
            'current_session' => ($auth['sid'] == $path['sid'])
        ];
    }
    
    public function killSession($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if($path['sid'] == 'current')
            $path['sid'] = $auth['sid'];
        
        if(!validateUintNz($path['sid']))
            throw new APIException(400, 'VALIDATION_ERROR', 'sid');
        
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
            throw new APIException(404, 'NOT_FOUND', 'Session '.$path['sid'].' not found');
    }
    
    public function getAllApiKeys($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(isset($query['offset']) && !validateUint($query['offset']))
            throw new APIException(400, 'VALIDATION_ERROR', 'offset');
        
        $offset = isset($query['offset']) ? $query['offset'] : 0;
        
        $task = array(
            ':uid' => $auth['uid'],
            ':offset' => $offset
        );
        
        $sql = "SELECT sid,
                       api_key,
                       ak_description,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact
               FROM sessions
               WHERE uid = :uid
               AND origin = 'API'
               ORDER BY sid DESC
               LIMIT 51
               OFFSET :offset";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $apiKeys = [];
        $more = false;
        
        while($row = $q -> fetch()) {
            if(count($apiKeys) == 50) {
                $more = true;
                break;
            }
            
            $apiKeys[] = [
                'keyid' => $row['sid'],
                'api_key' => $row['api_key'],
                'description' => $row['ak_description'],
                'lastact' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null
            ];
        }
        
        return [
            'api_keys' => $apiKeys,
            'more' => $more
        ];
    }
    
    public function getApiKey($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!validateUintNz($path['keyid']))
            throw new APIException(400, 'VALIDATION_ERROR', 'keyid');
        
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
            throw new APIException(404, 'NOT_FOUND', 'API key '.$path['keyid'].' not found');
        
        return [
             'keyid' => $path['keyid'],
             'api_key' => $row['api_key'],
             'description' => $row['ak_description'],
             'lastact' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null
        ];
    }
    
    public function deleteApiKey($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!validateUintNz($path['keyid']))
            throw new APIException(400, 'VALIDATION_ERROR', 'keyid');
        
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
            throw new APIException(404, 'NOT_FOUND', 'API key '.$path['keyid'].' not found');
    }
    
    public function addApiKey($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!isset($body['description']))
            throw new APIException(400, 'MISSING_DATA', 'description');
        
        if(!validateApiKeyDescription($body['description']))
            throw new APIException(400, 'VALIDATION_ERROR', 'description');
    
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
            throw new APIException(409, 'ALREADY_EXISTS', 'API key with this name already exists');
        
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
            'api_key' => $generatedApiKey
        ];
    }
    
    public function editApiKey($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!isset($body['description']))
            throw new APIException(400, 'MISSING_DATA', 'description');
        
        if(!validateUintNz($path['keyid']))
            throw new APIException(400, 'VALIDATION_ERROR', 'keyid');
        if(!validateApiKeyDescription($body['description']))
            throw new APIException(400, 'VALIDATION_ERROR', 'description');
    
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
            throw new APIException(409, 'ALREADY_EXISTS', 'API key with this name already exists');
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
            throw new APIException(404, 'NOT_FOUND', 'API key '.$path['keyid'].' not found');
    }
}

?>