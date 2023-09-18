<?php

require __DIR__.'/validate.php';

use Infinex\API\APIException;

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
        
        $rc -> get('/api_keys', [$this, 'getAllApiKeys']);
        $this -> log -> debug('Registered route GET /api_keys');
        
        $rc -> get('/api_keys/{keyid}', [$this, 'getApiKey']);
        $this -> log -> debug('Registered route GET /api_keys/{keyid}');
        
        $rc -> delete('/api_keys/{keyid}', [$this, 'deleteApiKey']);
        $this -> log -> debug('Registered route DELETE /api_keys/{keyid}');
        
        $rc -> post('/api_keys', [$this, 'addApiKey']);
        $this -> log -> debug('Registered route POST /api_keys');
        
        $rc -> patch('/api_keys/{keyid}', [$this, 'editApiKey']);
        $this -> log -> debug('Registered route PATCH /api_keys/{keyid}');
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
                'lastact' => $row['wa_lastact'],
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
    
    public function getSession($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
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
            'lastact' => $row['wa_lastact'],
            'browser' => $row['wa_browser'],
            'os' => $row['wa_os'],
            'device' => $row['wa_device'],
            'current_session' => ($auth['sid'] == $path['sid'])
        ];
    }
    
    public function killSession($path, $query, $body, $auth, $ua) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
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
                       ak_description
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
                'description' => $row['ak_description']
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
                       ak_description
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
             'keyid' => $row['sid'],
             'api_key' => $row['api_key'],
             'description' => $row['ak_description']
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
        
        if(!$this -> validateApiKeyDescription($body['description']))
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
            'sid' => $row['sid'],
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
        if(!$this -> validateApiKeyDescription($body['description']))
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
        
        // Update api key
        $task = array(
            ':uid' => $auth['uid'],
            ':sid' => $path['keyid'],
            ':description' => $body['description']
        );
        
        $sql = "UPDATE sessions
                SET ak_description = :ak_description
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