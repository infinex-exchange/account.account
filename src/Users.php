<?php

use Infinex\Exceptions\Error;
use Infinex\Pagination;
use function Infinex\Validation\validateId;
use function Infinex\Validation\validateEmail;
use React\Promise;

class Users {
    private $log;
    private $amqp;
    private $pdo;
    private $vc;
    
    function __construct($log, $amqp, $pdo, $vc) {
        $this -> log = $log;
        $this -> amqp = $amqp;
        $this -> pdo = $pdo;
        $this -> vc = $vc;
        
        $this -> log -> debug('Initialized users manager');
    }
    
    public function start() {
        $th = $this;
        
        $promises = [];
        
        $promises[] = $this -> amqp -> method(
            'getUsers',
            [$this, 'getUsers']
        );
        
        $promises[] = $this -> amqp -> method(
            'getUser',
            [$this, 'getUser']
        );
        
        $promises[] = $this -> amqp -> method(
            'createUser',
            [$this, 'createUser']
        );
        
        $promises[] = $this -> amqp -> method(
            'verifyUser',
            [$this, 'verifyUser']
        );
        
        $promises[] = $this -> amqp -> method(
            'changeEmail',
            [$this, 'changeEmail']
        );
        
        $promises[] = $this -> amqp -> method(
            'checkPassword',
            [$this, 'checkPassword']
        );
        
        $promises[] = $this -> amqp -> method(
            'changePassword',
            [$this, 'changePassword']
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
        
        $promises[] = $this -> amqp -> unreg('getUsers');
        $promises[] = $this -> amqp -> unreg('getUser');
        $promises[] = $this -> amqp -> unreg('createUser');
        $promises[] = $this -> amqp -> unreg('verifyUser');
        $promises[] = $this -> amqp -> unreg('changeEmail');
        $promises[] = $this -> amqp -> unreg('checkPassword');
        $promises[] = $this -> amqp -> unreg('changePassword');
        
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
    
    public function getUsers($body) {
        $pag = new Pagination\Offset(50, 500, $body);
        
        $sql = 'SELECT uid,
                       email,
                       verified,
                       EXTRACT(epoch FROM register_time) AS register_time
                       FROM users
                ORDER BY uid DESC'
              . $pag -> sql();
        
        $q = $this -> pdo -> query($sql);
        
        $users = [];
        
        while($row = $q -> fetch()) {
            if($pag -> iter()) break;
            $users[] = $this -> rtrUser($row);
        }
        
        return [
            'users' => $users,
            'more' => $pag -> more
        ];
    }
    
    public function getUser($body) {
        if(isset($body['uid']) && isset($body['email']))
            throw new Error('ARGUMENTS_CONFLICT', 'Both uid and email are set', 400);
        else if(isset($body['uid'])) {
            if(!validateId($body['uid']))
                throw new Error('VALIDATION_ERROR', 'uid');
        }
        else if(isset($body['email'])) {
            if(!validateEmail($body['email']))
                throw new Error('VALIDATION_ERROR', 'email', 400);
        }
        else
            throw new Error('MISSING_DATA', 'email or uid');
        
        $task = [];
        
        $sql = 'SELECT uid,
                       email,
                       verified,
                       EXTRACT(epoch FROM register_time) AS register_time
                FROM users';
        
        if(isset($body['uid'])) {
            $task[':uid'] = $body['uid'];
            $sql .= ' WHERE uid = :uid';
            $msgUser = $body['uid'];
        }
        else {
            $task[':email'] = strtolower($body['email']);
            $sql .= ' WHERE email = :email';
            $msgUser = $task[':email'];
        }
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'User '.$msgUser.' does not exists', 404);
        
        return $this -> rtrUser($row);
    }
    
    public function createUser($body) {
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        if(!$this -> validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
        
        $email = strtolower($body['email']);
        $hashedPassword = password_hash($body['password'], PASSWORD_DEFAULT);
    
        $task = array(
            ':email' => $email,
            ':password' => $hashedPassword
        );
        
        // Insert user
        $sql = 'INSERT INTO users (
            email,
            password,
            verified,
            register_time
        )
        VALUES (
            :email,
            :password,
            FALSE,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT DO NOTHING
        RETURNING uid';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        if(!$row)
            throw new Error('CONFLICT', 'This e-mail address is already in use', 409);
        
        $uid = $row['uid'];
        
        $this -> amqp -> pub(
            'registerUser',
            [
                'uid' => $uid,
                'refid' => @$body['refid']
            ],
            [
                'affiliation' => isset($body['refid'])
            ]
        );
        
        // Generate verification code
        $generatedCode = $this -> vc -> createCode(
            $uid,
            'REGISTER_USER'
        );
        
        // Send verification email
        $this -> amqp -> pub(
            'mail',
            [
                'uid' => $uid,
                'template' => 'register_user',
                'context' => [
                    'code' => $generatedCode
                ],
                'email' => $email
            ]
        );
        
        return $uid;
    }
    
    public function verifyUser($body) {
        if(!isset($body['uid']))
            throw new Error('MISSING_DATA', 'uid', 400);
        
        if(!validateId($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        
        $this -> pdo -> beginTransaction();
    
        $task = array(
            ':uid' => $body['uid']
        );
        
        $sql = "SELECT verified
                FROM users
                WHERE uid = :uid
                FOR UPDATE";
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row) {
            $this -> pdo -> rollBack();
            throw new Error('NOT_FOUND', 'User '.$body['uid'].' does not exists', 404);
        }
        
        if($row['verified']) {
            $this -> pdo -> rollBack();
            throw new Error('CONFLICT', 'User account already verified', 409);
        }
        
        $sql = 'UPDATE users
                SET verified = TRUE
                WHERE uid = :uid
                RETURNING 1';
        
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        
        $this -> pdo -> commit();
    }
    
    public function changeEmail($body) {
        if(!isset($body['uid']))
            throw new Error('MISSING_DATA', 'uid', 400);
        if(!isset($body['email']))
            throw new Error('MISSING_DATA', 'email', 400);
        
        if(!validateId($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(!validateEmail($body['email']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        
        $email = strtolower($body['email']);
        
        $task = array(
            ':uid' => $body['uid'],
            ':email' => $email
        );
    
        $sql = 'UPDATE users
                SET email = :email
                WHERE uid = :uid
                RETURNING 1';
    
        $q = $this -> pdo -> prepare($sql);
        try {
            $q -> execute($task);
        } catch(\PDOException $e) {
            if($e -> getCode() != 23505) throw $e;
            throw new Error('CONFLICT', 'This e-mail address is already in use', 409);
        }
        
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'User '.$body['uid'].' does not exists', 404);
    }
    
    public function checkPassword($body) {
        if(!isset($body['uid']))
            throw new Error('MISSING_DATA', 'uid', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        
        if(!validateId($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(!$this -> validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'email', 400);
        
        $task = array(
            ':uid' => $body['uid']
        );
        
        $sql = 'SELECT password
                FROM users
                WHERE uid = :uid';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'User '.$body['uid'].' does not exists', 404);
        
        if(!password_verify($body['password'], $row['password']))
            throw new Error('WRONG_PASSWORD', 'Wrong password', 401);
    }
    
    public function changePassword($body) {
        if(!isset($body['uid']))
            throw new Error('MISSING_DATA', 'uid', 400);
        if(!isset($body['password']))
            throw new Error('MISSING_DATA', 'password', 400);
        
        if(!validateId($body['uid']))
            throw new Error('VALIDATION_ERROR', 'uid', 400);
        if(!$this -> validatePassword($body['password']))
            throw new Error('VALIDATION_ERROR', 'password', 400);
    
        $hashedPassword = password_hash($body['password'], PASSWORD_DEFAULT);
    
        $task = array(
            ':uid' => $body['uid'],
            ':password' => $hashedPassword
        );
    
        $sql = 'UPDATE users
                SET password = :password
                WHERE uid = :uid
                RETURNING 1';
    
        $q = $this -> pdo -> prepare($sql);
        $q -> execute($task);
        $row = $q -> fetch();
        
        if(!$row)
            throw new Error('NOT_FOUND', 'User '.$body['uid'].' does not exists', 404);
    }
    
    public function validatePassword($pw) {
        if(strlen($pw) < 8) return false;
        if(strlen($pw) > 254) return false;
        if(!preg_match('#[A-Z]+#', $pw)) return false;
        if(!preg_match('#[a-z]+#', $pw)) return false;
        if(!preg_match('#[0-9]+#', $pw)) return false;
        return true;
    }
    
    private function rtrUser($row) {
        return [
            'uid' => $row['uid'],
            'email' => $row['email'],
            'verified' => $row['verified'],
            'registerTime' => intval($row['register_time'])
        ];
    }
}

?>