<?php

require_once __DIR__.'/validate.php';

use Infinex\API\APIException;

class MFAAPI {
    private $log;
    private $amqp;
    private $pdo;
    private $mfa;
    
    private $mapCaseToCol = [
        'LOGIN' => 'for_login_2fa',
        'WITHDRAWAL' => 'for_withdraw_2fa'
    ];
    
    function __construct($log, $amqp, $pdo, $mfa) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> mfa = $mfa;
        
        $this -> log -> debug('Initialized MFA API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/2fa/cases', [$this, 'getCases']);
        $this -> log -> debug('Registered route GET /2fa/cases');
        
        $rc -> patch('/2fa/cases', [$this, 'updateCases']);
        $this -> log -> debug('Registered route PATCH /2fa/cases');
    }
    
    public function getCases($path, $query, $body, $auth) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = 'SELECT for_login_2fa,
                       for_withdraw_2fa 
                FROM users
                WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        $cases = [];
        foreach($this -> mapCaseToCol as $k => $v)
        
        return [
            'cases' => $cases
        ];
    }
    
    public function updateCases($path, $query, $body, $auth) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!isset($body['cases']))
            throw new APIException(400, 'MISSING_DATA', 'cases');
        
        if(!is_array($body['cases']))
            throw new APIException(400, 'VALIDATION_ERROR', 'cases is not an array');
        foreach($body['cases'] as $k => $v) {
            if(array_key_exists($k, $this -> mapCaseToCol))
                throw new APIException(400, 'VALIDATION_ERROR', 'cases contains an invalid key');
            if(!is_bool($v))
                throw new APIException(400, 'VALIDATION_ERROR', 'cases contains a non-boolean value');
        }
        
        if(isset($body['code_2fa']) && !validate2FA($body['code_2fa']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code_2fa');
        
        if(isset($body['code_2fa'])) {
            if(!$this -> mfa -> response($auth['uid'], 'config2fa', 'config2fa', $body['cases'], $body['code_2fa']))
                throw new APIException(401, 'INVALID_2FA', 'Invalid 2FA code');
        }
        else {
            $prov = $this -> mfa -> challenge($auth['uid'], 'config2fa', 'config2fa', $body['cases']);
            if($prov != null)
                throw new APIException(511, 'REQUIRE_2FA', $prov);
        }
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = 'UPDATE users
                SET uid = uid';
        
        foreach($body['cases'] as $case => $bool) {
            $col = $this -> mapCaseToCol[$case];
            $sql .= ", $col = :$col";
            $task[":$col"] = $bool ? 1 : 0;
        }
        
        $sql .= ' WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
    }
}

?>