<?php

require_once __DIR__.'/validate.php';

use Infinex\API\APIException;
use PragmaRX\Google2FA\Google2FA;

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
        
        $rc -> get('/2fa/providers', [$this, 'getProviders']);
        $this -> log -> debug('Registered route GET /2fa/providers');
        
        $rc -> put('/2fa/providers/{prov}', [$this, 'configureProvider']);
        $this -> log -> debug('Registered route PUT /2fa/providers/{prov}');
        
        $rc -> post('/2fa/providers/{prov}', [$this, 'enableProvider']);
        $this -> log -> debug('Registered route POST /2fa/providers/{prov}');
        
        $rc -> delete('/2fa/providers/{prov}', [$this, 'resetProvider']);
        $this -> log -> debug('Registered route DELETE /2fa/providers/{prov}');
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
            $cases[$k] = $row[$v];
        
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
            if(!array_key_exists($k, $this -> mapCaseToCol))
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
    
    public function getProviders($path, $query, $body, $auth) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = 'SELECT provider_2fa, 
                       ga_secret_2fa
                FROM users
                WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        return [
            'providers' => [
                'EMAIL' => [
                    'configured' => true,
                    'enabled' => ($row['provider_2fa'] == 'EMAIL')
                ],
                'GA' => [
                    'configured' => ($row['ga_secret_2fa'] != NULL),
                    'enabled' => ($row['provider_2fa'] == 'GA')
                ]
            ]
        ];
    }
    
    public function configureProvider($path, $query, $body, $auth) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!in_array($path['prov'], ['EMAIL', 'GA']))
            throw new APIException(404, 'NOT_FOUND', 'Unknown provider');
        
        if($path['prov'] == 'EMAIL')
            throw new APIException(409, 'ALREADY_EXISTS', 'Already configured');
        // Keep in mind when adding next providers
        
        if(isset($body['code_2fa']) && !validate2FA($body['code_2fa']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code_2fa');
        
        if(isset($body['code_2fa'])) {
            if(!$this -> mfa -> response($auth['uid'], 'config2fa', 'config2fa', [ 'config' => $path['prov'] ], $body['code_2fa']))
                throw new APIException(401, 'INVALID_2FA', 'Invalid 2FA code');
        }
        else {
            $prov = $this -> mfa -> challenge($auth['uid'], 'config2fa', 'config2fa', [ 'config' => $path['prov'] ]);
            if($prov != null)
                throw new APIException(511, 'REQUIRE_2FA', $prov);
        }
        
        $google2fa = new Google2FA();
        $userSecret = $google2fa -> generateSecretKey();
        
        $task = array(
            ':uid' => $auth['uid'],
            ':ga_secret_2fa' => $userSecret
        );
        
        $sql = 'UPDATE users
                SET ga_secret_2fa = :ga_secret_2fa
                WHERE uid = :uid
                AND ga_secret_2fa IS NULL
                RETURNING email';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $row = $q -> fetch();
        if(!$row)
            throw new APIException(409, 'ALREADY_EXISTS', 'Already configured');
        
        $qr = $google2fa -> getQRCodeUrl(
            'Infinex',
            $row['email'],
            $userSecret
        );
        
        return [
            'ga_qr' => $qr
        ];
    }
    
    public function enableProvider($path, $query, $body, $auth) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!in_array($path['prov'], ['EMAIL', 'GA']))
            throw new APIException(404, 'NOT_FOUND', 'Unknown provider');
        
        if(isset($body['code_2fa']) && !validate2FA($body['code_2fa']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code_2fa');
        
        if(isset($body['code_2fa'])) {
            if(!$this -> mfa -> response($auth['uid'], 'config2fa', 'config2fa', [ 'enable' => $path['prov'] ], $body['code_2fa']))
                throw new APIException(401, 'INVALID_2FA', 'Invalid 2FA code');
        }
        else {
            $prov = $this -> mfa -> challenge($auth['uid'], 'config2fa', 'config2fa', [ 'enable' => $path['prov'] ]);
            if($prov != null)
                throw new APIException(511, 'REQUIRE_2FA', $prov);
        }
        
        $this -> pdo -> beginTransaction();
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = 'SELECT ga_secret_2fa,
                       provider_2fa
                FROM users
                WHERE uid = :uid
                FOR UPDATE';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $row = $q -> fetch();
        
        if($path['prov'] == $row['provider_2fa']) {
            $this -> pdo -> rollBack();
            return;
        }
        
        if($path['prov'] == 'GA' && $row['ga_secret_2fa'] == NULL) {
            $this -> pdo -> rollBack();
            throw new APIException(403, 'NOT_CONFIGURED', 'Cannot enable unconfigured provider');
        }
        
        $task = array(
            ':uid' => $auth['uid'],
            ':provider_2fa' => $path['prov']
        );
        
        $sql = 'UPDATE users
                SET provider_2fa = :provider_2fa
                WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
    }
    
    public function resetProvider($path, $query, $body, $auth) {
        if(!$auth)
            throw new APIException(401, 'UNAUTHORIZED', 'Unauthorized');
        
        if(!in_array($path['prov'], ['EMAIL', 'GA']))
            throw new APIException(404, 'NOT_FOUND', 'Unknown provider');
        
        if($path['prov'] == 'EMAIL')
            throw new APIException(423, 'DEFAULT_PROVIDER', 'Cannot reset default e-mail provider');
        // Keep in mind when adding next providers
        
        if(isset($body['code_2fa']) && !validate2FA($body['code_2fa']))
            throw new APIException(400, 'VALIDATION_ERROR', 'code_2fa');
        
        if(isset($body['code_2fa'])) {
            if(!$this -> mfa -> response($auth['uid'], 'config2fa', 'config2fa', [ 'reset' => $path['prov'] ], $body['code_2fa']))
                throw new APIException(401, 'INVALID_2FA', 'Invalid 2FA code');
        }
        else {
            $prov = $this -> mfa -> challenge($auth['uid'], 'config2fa', 'config2fa', [ 'reset' => $path['prov'] ]);
            if($prov != null)
                throw new APIException(511, 'REQUIRE_2FA', $prov);
        }
        
        $task = array(
            ':uid' => $auth['uid']
        );
        
        $sql = "UPDATE users
                SET ga_secret_2fa = NULL,
                    provider_2fa = 'EMAIL'
                WHERE uid = :uid
                AND ga_secret_2fa IS NOT NULL
                RETURNING 1";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new APIException(409, 'ALREADY_EXISTS', 'Provider already not configured');
    }
}

?>