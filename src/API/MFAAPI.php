<?php

use Infinex\Exceptions\Error;
use PragmaRX\Google2FA\Google2FA;

class MFAAPI {
    private $log;
    private $pdo;
    private $mfa;
    
    private $mapCaseToCol = [
        'LOGIN' => 'for_login_2fa',
        'WITHDRAWAL' => 'for_withdraw_2fa'
    ];
    
    function __construct($log, $pdo, $mfa) {
        $this -> log = $log;
        $this -> pdo = $pdo;
        $this -> mfa = $mfa;
        
        $this -> log -> debug('Initialized MFA API');
    }
    
    public function initRoutes($rc) {
        $rc -> get('/2fa/cases', [$this, 'getCases']);
        $rc -> patch('/2fa/cases', [$this, 'updateCases']);
        $rc -> get('/2fa/providers', [$this, 'getProviders']);
        $rc -> put('/2fa/providers/{prov}', [$this, 'configureProvider']);
        $rc -> post('/2fa/providers/{prov}', [$this, 'enableProvider']);
        $rc -> delete('/2fa/providers/{prov}', [$this, 'resetProvider']);
    }
    
    public function getCases($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
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
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!isset($body['cases']))
            throw new Error('MISSING_DATA', 'cases', 400);
        
        if(!is_array($body['cases']))
            throw new Error('VALIDATION_ERROR', 'cases is not an array', 400);
        foreach($body['cases'] as $k => $v) {
            if(!array_key_exists($k, $this -> mapCaseToCol))
                throw new Error('VALIDATION_ERROR', 'cases contains an invalid key', 400);
            if(!is_bool($v))
                throw new Error('VALIDATION_ERROR', 'cases contains a non-boolean value', 400);
        }
        
        $this -> mfa -> mfa(
            $auth['uid'],
            null,
            'config2fa',
            $body['cases'],
            isset($body['code2FA']) ? $body['code2FA'] : null
        );
        
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
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
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
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!in_array($path['prov'], ['EMAIL', 'GA']))
            throw new Error('NOT_FOUND', 'Unknown provider', 404);
        
        if($path['prov'] == 'EMAIL')
            throw new Error('ALREADY_EXISTS', 'Already configured', 409);
        // Keep in mind when adding next providers
        
        $this -> mfa -> mfa(
            $auth['uid'],
            null,
            'config2fa',
            [ 'config' => $path['prov'] ],
            isset($body['code2FA']) ? $body['code2FA'] : null
        );
        
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
            throw new Error('ALREADY_EXISTS', 'Already configured', 409);
        
        $qr = $google2fa -> getQRCodeUrl(
            'Infinex',
            $row['email'],
            $userSecret
        );
        
        return [
            'url' => $qr
        ];
    }
    
    public function enableProvider($path, $query, $body, $auth) {
        if(!$auth)
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!in_array($path['prov'], ['EMAIL', 'GA']))
            throw new Error('NOT_FOUND', 'Unknown provider', 404);
        
        $this -> mfa -> mfa(
            $auth['uid'],
            null,
            'config2fa',
            [ 'enable' => $path['prov'] ],
            isset($body['code2FA']) ? $body['code2FA'] : null
        );
        
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
            throw new Error('NOT_CONFIGURED', 'Cannot enable unconfigured provider', 403);
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
            throw new Error('UNAUTHORIZED', 'Unauthorized', 401);
        
        if(!in_array($path['prov'], ['EMAIL', 'GA']))
            throw new Error('NOT_FOUND', 'Unknown provider', 404);
        
        if($path['prov'] == 'EMAIL')
            throw new Error('DEFAULT_PROVIDER', 'Cannot reset default e-mail provider', 423);
        // Keep in mind when adding next providers
        
        $this -> mfa -> mfa(
            $auth['uid'],
            null,
            'config2fa',
            [ 'reset' => $path['prov'] ],
            isset($body['code2FA']) ? $body['code2FA'] : null
        );
        
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
            throw new Error('ALREADY_EXISTS', 'Provider already not configured', 409);
    }
}

?>