<?php

use React\Promise;
use PragmaRX\Google2FA\Google2FA;

class MFA {
    private $log;
    private $amqp;
    private $pdo;
    
    function __construct($log, $amqp, $pdo) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized MFA');
    }
    
    public function start() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> method(
            'mfa',
            function($body) use($th) {
                return $th -> mfa(
                    $body['uid'],
                    $body['group'],
                    $body['action'],
                    $body['context'],
                    $body['code']
                );
            }
        );
        
        return Promise\all($promises) -> then(
            function() use($th) {
                $th -> log -> info('Started MFA');
            }
        ) -> catch(
            function($e) use($th) {
                $th -> log -> error('Failed to start MFA: '.((string) $e));
                throw $e;
            }
        );
    }
    
    public function stop() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> unreg('mfa');
        
        return Promise\all($promises) -> then(
            function() use ($th) {
                $th -> log -> info('Stopped MFA');
            }
        ) -> catch(
            function($e) use($th) {
                $th -> log -> error('Failed to stop MFA: '.((string) $e));
            }
        );
    }
    
    public function mfa($uid, $group, $action, $context, $code) {
        if($code) {
            if(! $this -> validateMFACode($code))
                throw new Error('VALIDATION_ERROR', 'Invalid 2FA code format', 400);
        
            if(! $this -> response($uid, $group, $action, $context, $code))
                throw new Error('INVALID_2FA', 'Invalid 2FA code', 401);
        }
        else {
            $prov = $this -> challenge($uid, $group, $action, $context);
            if($prov !== null)
                throw new Error('REQUIRE_2FA', $prov, 511);
        }
    }
    
    private function challenge($uid, $group, $action, $context) {
        $task = array(
            ':uid' => $uid
        );
        
        $sql = 'SELECT email,
                       provider_2fa';
        if($group)
            $sql.= ', for_'.$group.'_2fa AS enabled';
        $sql .= ' FROM users
                  WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($group && !$row['enabled'])
            return null;
        
        if($row['provider_2fa'] == 'EMAIL') {
            $generatedCode = sprintf('%06d', rand(0, 999999));
            
            $task = array(
                ':uid' => $uid,
                ':code' => $generatedCode,
                ':context_data' => md5($group.$action.json_encode($context))
            );
            
            $sql = "INSERT INTO email_codes (
                uid,
                context,
                code,
                context_data
            )
            VALUES (
                :uid,
                '2FA',
                :code,
                :context_data
            )";
          
            $q = $this -> pdo -> prepare($sql);
            $q -> execute($task);
          
            $context['code'] = $generatedCode;
            
            $this -> amqp -> pub(
                'mail',
                [
                    'uid' => $uid,
                    'template' => '2fa_'.$action,
                    'context' => $context,
                    'email' => $row['email']
                ]
            );
            
            return 'EMAIL:'.$row['email'];
        }
        
        else {
            return 'GA';
        }
    }
    
    private function response($uid, $group, $action, $context, $code) {
        $task = array(
            ':uid' => $uid
        );
        
        $sql = 'SELECT provider_2fa,
                       ga_secret_2fa';
        if($group)
            $sql.= ', for_'.$group.'_2fa AS enabled';
        $sql .= ' FROM users
                  WHERE uid = :uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($group && !$row['enabled'])
            return false;
        
        if($row['provider_2fa'] == 'EMAIL') {
            $task = array(
                ':uid' => $uid,
                ':code' => $code,
                ':context_data' => md5($group.$action.json_encode($context))
            );
            
            $sql = "DELETE FROM email_codes
                    WHERE uid = :uid
                    AND code = :code
                    AND context_data = :context_data
                    RETURNING 1";
          
            $q = $this -> pdo -> prepare($sql);
            $q -> execute($task);
            $row = $q -> fetch();
            
            if($row)
                return true;
            return false;
        }
        
        else {
            $google2fa = new Google2FA();
            return $google2fa -> verifyKey($row['ga_secret_2fa'], $code);
        }
    }
    
    private function validateMFACode($code) {
        return preg_match('/^[0-9]{6}$/', $code);
    }
}

?>