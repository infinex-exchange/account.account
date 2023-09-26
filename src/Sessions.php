<?php

use Infinex\Exceptions\Error;

class Sessions {
    private $log;
    private $amqp;
    private $pdo;
    
    function __construct($log, $amqp, $pdo) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized sessions manager');
    }
    
    public function start() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> method(
            'checkApiKey',
            function($body) use($th) {
                return $th -> checkApiKey(
                    $body['apiKey']
                );
            }
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
    
    public function checkApiKey($apiKey) {
        if(!$this -> validateApiKey($apiKey))
            throw new Error('VALIDATION_ERROR', 'Invalid API key format', 400);
        
        $task = array(
            ':api_key' => $apiKey
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
    
    private function validateApiKey($apiKey) {
        return preg_match('/^[a-f0-9]{64}$/', $apiKey);
    }
}

?>