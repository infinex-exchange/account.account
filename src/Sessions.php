<?php

use Infinex\Exceptions\Error;
use Infinex\Pagination;
use React\Promise;

class Sessions {
    private $log;
    private $amqp;
    private $pdo;
    private $users;
    
    function __construct($log, $amqp, $pdo, $users) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> users = $users;
        
        $this -> log -> debug('Initialized sessions manager');
    }
    
    public function start() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> method(
            'checkApiKey',
            [$this, 'checkApiKey']
        );
        
        $promises[] = $this -> amqp -> method(
            'getSessions',
            [$this, 'getSession']
        );
        
        $promises[] = $this -> amqp -> method(
            'killSession',
            [$this, 'killSession']
        );
        
        $promises[] = $this -> amqp -> method(
            'createSession',
            [$this, 'createSession']
        );
        
        $promises[] = $this -> amqp -> method(
            'editSession',
            [$this, 'editSession']
        );
        
        return Promise\all($promises) -> then(
            function() use($th) {
                $th -> log -> info('Started sessions manager');
            }
        ) -> catch(
            function($e) use($th) {
                $th -> log -> error('Failed to start sessions manager: '.((string) $e));
                throw $e;
            }
        );
    }
    
    public function stop() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> unreg('checkApiKey');
        
        return Promise\all($promises) -> then(
            function() use ($th) {
                $th -> log -> info('Stopped sessions manager');
            }
        ) -> catch(
            function($e) use($th) {
                $th -> log -> error('Failed to stop sessions manager: '.((string) $e));
            }
        );
    }
    
    public function checkApiKey($body) {
        if(!isset($body['apiKey']))
            throw new Error('MISSING_DATA', 'apiKey', 400);
            
        if(!$this -> validateApiKey($body['apiKey']))
            throw new Error('VALIDATION_ERROR', 'Invalid API key format', 400);
        
        $task = array(
            ':api_key' => $body['apiKey']
        );
        
        $sql = 'UPDATE sessions
                SET wa_lastact = CURRENT_TIMESTAMP
                WHERE api_key = :api_key
                RETURNING sid,
                          uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('UNAUTHORIZED', 'Invalid API key', 401);
        
        return [
            'uid' => $row['uid'],
            'sid' => $row['sid']
        ];
    }
    
    public function getSessions($body) {
        if(isset($body['uid']) && ! $this -> users -> validateUid($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(isset($body['origin']) && !in_array($body['origin'], ['WEBAPP', 'API']))
            throw new Error('VALIDATION_ERROR', 'origin', 400);
        
        $pag = new Pagination\Offset(50, 500, $body);
        
        $task = array();
        
        $sql = 'SELECT sid,
                       uid,
                       api_key,
                       origin,
                       wa_remember,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact,
                       wa_browser,
                       wa_os,
                       wa_device,
                       ak_description
               FROM sessions
               WHERE 1=1';
        
        if(isset($body['uid'])) {
            $task[':uid'] = $body['uid'];
            $sql .= ' AND uid = :uid';
        }
        
        if(isset($body['origin'])) {
            $task[':origin'] = $body['origin'];
            $sql .= ' AND origin = :origin';
        }
        
        $sql .= ' ORDER BY sid DESC'
             . $pag -> sql();
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $sessions = [];
        
        while($row = $q -> fetch()) {
            if($pag -> iter()) break;
            $sessions[] = $this -> rtrSession($row);
        }
        
        return [
            'sessions' => $sessions,
            'more' => $pag -> more
        ];
    }
    
    public function getSession($body) {
        if(!isset($body['sid']))
            throw new Error('MISSING_DATA', 'sid', 400);
        
        if(!$this -> validateSid($body['sid']))
            throw new Error('VALIDATION_ERROR', 'sid', 400);
        if(isset($body['uid']) && ! $this -> users -> validateUid($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(isset($body['origin']) && !in_array($body['origin'], ['WEBAPP', 'API']))
            throw new Error('VALIDATION_ERROR', 'origin', 400);
        
        $task = array(
            ':sid' => $body['sid']
        );
        
        $sql = 'SELECT sid,
                       uid,
                       api_key,
                       origin,
                       wa_remember,
                       EXTRACT(epoch FROM wa_lastact) AS wa_lastact,
                       wa_browser,
                       wa_os,
                       wa_device,
                       ak_description
               FROM sessions
               WHERE sid = :sid';
        
        if(isset($body['uid'])) {
            $task[':uid'] = $body['uid'];
            $sql .= ' AND uid = :uid';
        }
        
        if(isset($body['origin'])) {
            $task[':origin'] = $body['origin'];
            $sql .= ' AND origin = :origin';
        }
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        if(!$row)
            throw new Error('NOT_FOUND', 'Session '.$body['sid'].' not found', 404);
        
        return $this -> rtrSession($row);
    }
    
    public function killSession($body) {
        if(!isset($body['sid']))
            throw new Error('MISSING_DATA', 'sid', 400);
        
        if(!$this -> validateSid($body['sid']))
            throw new Error('VALIDATION_ERROR', 'sid', 400);
        if(isset($body['uid']) && ! $this -> users -> validateUid($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(isset($body['origin']) && !in_array($body['origin'], ['WEBAPP', 'API']))
            throw new Error('VALIDATION_ERROR', 'origin', 400);
        
        $task = array(
            ':sid' => $body['sid']
        );
        
        $sql = 'DELETE FROM sessions
                WHERE sid = :sid';
        
        if(isset($body['uid'])) {
            $task[':uid'] = $body['uid'];
            $sql .= ' AND uid = :uid';
        }
        
        if(isset($body['origin'])) {
            $task[':origin'] = $body['origin'];
            $sql .= ' AND origin = :origin';
        }
        
        $sql .= ' RETURNING 1';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'Session '.$body['sid'].' not found', 404);
    }
    
    public function createSession($body) {
        if(!isset($body['uid']))
            throw new Error('MISSING_DATA', 'uid', 400);
        if(!isset($body['origin']))
            throw new Error('MISSING_DATA', 'origin', 400);
        
        if(! $this -> users -> validateUid($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(!in_array($body['origin'], ['WEBAPP', 'API']))
            throw new Error('VALIDATION_ERROR', 'origin', 400);
        
        if($body['origin'] == 'WEBAPP') {
            if(!isset($body['browser']))
                throw new Error('MISSING_DATA', 'browser', 400);
            if(!isset($body['os']))
                throw new Error('MISSING_DATA', 'os', 400);
            if(!isset($body['device']))
                throw new Error('MISSING_DATA', 'device', 400);
            
            if(isset($body['remember']) && !is_bool($body['remember']))
                throw new Error('VALIDATION_ERROR', 'remember', 400);
        }
        else {
            if(!isset($body['description']))
                throw new Error('MISSING_DATA', 'description', 400);
            
            if(! $this -> validateApiKeyDescription($body['description']))
                throw new Error('VALIDATION_ERROR', 'description', 400);
            
            // Check api key with this name already exists
            $task = array(
                ':uid' => $body['uid'],
                ':description' => $body['description']
            );
            
            $sql = "SELECT 1
                    FROM sessions
                    WHERE uid = :uid
                    AND ak_description = :description
                    AND origin = 'API'";
            
            $q = $this -> pdo -> prepare($sql);
            $q -> execute($task);
            $row = $q -> fetch();
            
            if($row)
                throw new Error('CONFLICT', 'API key with this name already exists', 409);
        }
        
        // Generate and insert api key
        $generatedApiKey = bin2hex(random_bytes(32));
        
        if($body['origin'] == 'WEBAPP') {
            if(@$body['remember'])
                $remember = 1;
            else
                $remember = 0;
        }
        else
            $remember = null;
        
        $task = array(
            ':uid' => $body['uid'],
            ':api_key' => $generatedApiKey,
            ':origin' => $body['origin'],
            ':wa_remember' => $remember,
            ':wa_browser' => $body['origin'] == 'WEBAPP' ? $body['browser'] : null,
            ':wa_os' => $body['origin'] == 'WEBAPP' ? $body['os'] : null,
            ':wa_device' => $body['origin'] == 'WEBAPP' ? $body['device'] : null,
            ':ak_description' => $body['origin'] == 'API' ? $body['description'] : null,
        );
        
        $sql = 'INSERT INTO sessions(
                    uid,
                    api_key,
                    origin,
                    wa_remember,
                    wa_browser,
                    wa_os,
                    wa_device,
                    ak_description
                ) VALUES (
                    :uid,
                    :api_key,
                    :origin,
                    :wa_remember,
                    :wa_os,
                    :wa_device,
                    :ak_description
                )
                RETURNING sid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        return [
            'sid' => $row['sid'],
            'apiKey' => $generatedApiKey
        ];
    }
    
    public function editSession($body) {
        if(!isset($body['sid']))
            throw new Error('MISSING_DATA', 'sid', 400);
        if(!isset($body['description']))
            throw new Error('MISSING_DATA', 'description', 400);
        
        if(!$this -> validateSid($body['sid']))
            throw new Error('VALIDATION_ERROR', 'sid', 400);
        if(!$this -> validateApiKeyDescription($body['description']))
            throw new Error('VALIDATION_ERROR', 'description', 400);
        if(isset($body['uid']) && ! $this -> users -> validateUid($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
            
        if(isset($body['uid']))
            $uid = $body['uid'];
        else {
            // Get uid
            $task = array(
                ':sid' => $body['sid']
            );
            
            $sql = 'SELECT uid
                    FROM sessions
                    WHERE sid = :sid';
            
            $q = $this -> pdo -> prepare($sql);
            $q -> execute($task);
            $row = $q -> fetch();
            
            if(!$row)
                throw new Error('NOT_FOUND', 'API key '.$body['sid'].' not found', 404);
            
            $uid = $row['uid'];
        }
        
        $this -> pdo -> beginTransaction();
        
        // Check api key with this name already exists
        $task = array(
            ':uid' => $uid,
            ':description' => $body['description'],
            ':sid' => $body['sid']
        );
        
        $sql = "SELECT 1
                FROM sessions
                WHERE uid = :uid
                AND ak_description = :description
                AND origin = 'API'
                AND sid != :sid
                FOR UPDATE";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($row) {
            $this -> pdo -> rollBack();
            throw new Error('CONFLICT', 'API key with this name already exists', 409);
        }
    
        // Update api key
        
        $sql = "UPDATE sessions
                SET ak_description = :description
                WHERE uid = :uid
                AND sid = :sid
                AND origin = 'API'
                RETURNING 1";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row) {
            $this -> pdo -> rollBack();
            throw new Error('NOT_FOUND', 'API key '.$body['sid'].' not found', 404);
        }
        
        $this -> pdo -> commit();
    }
    
    private function validateSid($sid) {
        if(!is_int($sid)) return false;
        if($sid < 1) return false;
        return true;
    }
    
    private function validateApiKey($apiKey) {
        return preg_match('/^[a-f0-9]{64}$/', $apiKey);
    }
    
    private function validateApiKeyDescription($desc) {
        return preg_match('/^[a-zA-Z0-9 ]{1,255}$/', $desc);
    }
    
    private function rtrSession($row) {
        return [
            'sid' => $row['sid'],
            'uid' => $row['uid'],
            'apiKey' => $row['api_key'],
            'origin' => $row['origin'],
            'remember' => $row['wa_remember'],
            'lastAct' => $row['wa_lastact'] ? intval($row['wa_lastact']) : null,
            'browser' => $row['browser'],
            'os' => $row['os'],
            'device' => $row['device'],
            'description' => $row['ak_description']
        ];
    }
}

?>