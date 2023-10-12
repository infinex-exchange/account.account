<?php

use Infinex\Exceptions\Error;
use React\Promise;

class VeriCodes {
    private $log;
    private $pdo;
    
    function __construct($log, $pdo) {
        $this -> log = $log;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized verification codes manager');
    }
    
    public function start() {
        $this -> log -> info('Started verification codes manager');
        return Promise\resolve(null);
    }
    
    public function stop() {
        $this -> log -> info('Stopped verification codes manager');
        return Promise\resolve(null);
    }
    
    public function createCode($uid, $context, $contextData = null, $deletePrev = true) {
        if($deletePrev)
            $this -> deletePrevCodes($uid, $context);
        
        $generatedCode = sprintf('%06d', rand(0, 999999));
        
        $task = array(
            ':uid' => $uid,
            ':context' => $context,
            ':code' => $generatedCode,
            ':context_data' => $contextData
        );
        
        $sql = "INSERT INTO email_codes (
            uid,
            context,
            code,
            context_data
        )
        VALUES (
            :uid,
            :context,
            :code,
            :context_data
        )";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        return $generatedCode;
    }
    
    public function useCode($uid, $context, $code, $contextData = null) {
        if(!isset($code))
            throw new Error('MISSING_DATA', 'code', 400);
        if(!$this -> validateVeriCode($code))
            throw new Error('VALIDATION_ERROR', 'code', 400);
        
        $task = array(
            ':uid' => $uid,
            ':context' => $context,
            ':code' => $generatedCode
        );
        if($contextData)
            $task[':context_data'] = $contextData;
        
        $sql = 'DELETE FROM email_codes
                WHERE uid = :uid
                AND context = :context
                AND code = :code';
        
        if($contextData)
            $sql .= ' AND context_data = :context_data';
        
        $sql .= ' RETURNING context_data';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('INVALID_VERIFICATION_CODE', 'Invalid verification code', 401);
        
        return $row['context_data'];
    }
    
    public function deletePrevCodes($uid, $context) {
        $task = [
            ':uid' => $uid,
            ':context' => $context
        ];
        
        $sql = 'DELETE FROM email_codes
                WHERE uid = :uid
                AND context = :context
                RETURNING 1';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            return false;
        return true;
    }
    
    private function validateVeriCode($code) {
        return preg_match('/^[0-9]{6}$/', $code);
    }
}

?>