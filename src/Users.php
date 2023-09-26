<?php

use Infinex\Exceptions\Error;

class Users {
    private $log;
    private $amqp;
    private $pdo;
    
    function __construct($log, $amqp, $pdo) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized users manager');
    }
    
    public function start() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> method(
            'uidToEmail',
            function($body) use($th) {
                return $th -> uidToEmail(
                    $body['uid']
                );
            }
        );
        
        return Promise\all($promises) -> then(
            function() use($th) {
                $th -> log -> info('Started users manager');
            }
        ) -> catch(
            function($e) use($th) {
                $th -> log -> error('Failed to start users manager: '.((string) $e));
                throw $e;
            }
        );
    }
    
    public function stop() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> unreg('uidToEmail');
        
        return Promise\all($promises) -> then(
            function() use ($th) {
                $th -> log -> info('Stopped users manager');
            }
        ) -> catch(
            function($e) use($th) {
                $th -> log -> error('Failed to stop users manager: '.((string) $e));
            }
        );
    }
    
    public function uidToEmail($uid) {
        if(!$this -> validateUid($uid))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        
        $task = array(
            ':uid' => $uid
        );
        
        $sql = 'SELECT email
                FROM users
                WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'User with uid='.$uid.' does not exists');
        
        return $row['email'];
    }
    
    private function validateUid($uid) {
        if(!is_int($uint)) return false;
        if($uint < 1) return false;
        return true;
    }
}

?>