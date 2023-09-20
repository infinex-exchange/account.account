<?php

use PragmaRX\Google2FA\Google2FA;

class MFA {
    private $log;
    private $amqp;
    private $pdo;
    
    function __construct($log, $amqp, $pdo) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        
        $this -> log -> debug('Initialized MFA module');
    }
    
    function challenge($uid, $actionGroup, $action, $context) {
        $task = array(
            ':uid' => $uid
        );
        
        $sql = null;
        
        if($actionGroup == 'config2fa') {
            $sql = 'SELECT email
                    FROM users
                    WHERE uid = :uid';
        }
        else {
            $sql = "SELECT email,
                           provider_2fa,
                           for_${actionGroup}_2fa AS enabled 
                FROM users
                WHERE uid = :uid";
        }
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($actionGroup != 'config2fa' && !$row['enabled'])
            return null;
        
        if($actionGroup == 'config2fa' || $row['provider_2fa'] == 'EMAIL') {
            $generatedCode = sprintf('%06d', rand(0, 999999));
            
            $task = array(
                ':uid' => $uid,
                ':code' => $generatedCode,
                ':context_data' => md5($actionGroup.$action.json_encode($context))
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
                    'email' => $row['email'],
                    'template' => '2fa_'.$action,
                    'context' => $context
                ]
            );
            
            return 'EMAIL:'.$row['email'];
        }
        
        else {
            return 'GA';
        }
    }
    
    function response($uid, $actionGroup, $action, $context, $code) {
        $task = array(
            ':uid' => $uid
        );
        
        $sql = null;
        
        if($actionGroup == 'config2fa') {
            $sql = 'SELECT email
                    FROM users
                    WHERE uid = :uid';
        }
        else {
            $sql = "SELECT email,
                           provider_2fa,
                           ga_secret_2fa,
                           for_${actionGroup}_2fa AS enabled 
                FROM users
                WHERE uid = :uid";
        }
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if($actionGroup != 'config2fa' && !$row['enabled'])
            return true;
        
        if($actionGroup == 'config2fa' || $row['provider_2fa'] == 'EMAIL') {
            $task = array(
                ':uid' => $uid,
                ':code' => $code,
                ':context_data' => md5($actionGroup.$action.json_encode($context))
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
}

?>