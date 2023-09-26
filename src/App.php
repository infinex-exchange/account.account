<?php

require __DIR__.'/Users.php';
require __DIR__.'/Sessions.php';
require __DIR__.'/MFA.php';

require __DIR__.'/API/MFAAPI.php';
require __DIR__.'/Signup.php';
require __DIR__.'/Sessions.php';
require __DIR__.'/Password.php';
require __DIR__.'/Email.php';

use React\Promise;

class App extends Infinex\App\App {
    private $pdo;
    
    private $users;
    private $sessions;
    private $mfa;
    
    private $rest;
    private $mfaApi;
    private $sessionsApi;
    private $password;
    private $email;
    
    function __construct() {
        parent::__construct('account.accountd');
        
        $this -> pdo = new Infinex\Database\PDO(
            $this -> loop,
            $this -> log,
            DB_HOST,
            DB_USER,
            DB_PASS,
            DB_NAME
        );
        
        $this -> users = new Users(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
        
        $this -> sessions = new Sessions(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
        
        $this -> mfa = new MFA(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
        
        $this -> rest = new Infinex\API\REST(
            $this -> log,
            $this -> amqp
        );
        
        $this -> mfaApi = new MFAAPI(
            $this -> log,
            $this -> pdo,
            $this -> rest,
            $this -> mfa
        );
        
        $this -> sessionsApi = new SessionsAPI(
            $this -> log,
            $this -> pdo,
            $this -> rest,
            $this -> mfa
        );
        
        $this -> email = new Email(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
    }
    
    public function start() {
        $th = $this;
        
        parent::start() -> then(
            function() use($th) {
                return $th -> pdo -> start();
            }
        ) -> then(
            function() use($th) {
                return Promise\all([
                    $th -> mfa -> start(),
                    $th -> signup -> start(),
                    $th -> password -> start(),
                    $th -> email -> start()
                ]);
            }
        ) -> then(
            function() use($th) {
                return $th -> sessions -> start();
            }
        ) -> then(
            function() use($th) {
                return $th -> rest -> start();
            }
        ) -> catch(
            function($e) {
                $th -> log -> error('Failed start app: '.((string) $e));
            }
        );
    }
    
    public function stop() {
        $th = $this;
        
        $this -> rest -> stop() -> then(
            function() use($th) {
                return $th -> sessions -> stop();
            }
        ) -> then(
            function() use($th) {
                return Promise\all([
                    $th -> mfa -> stop(),
                    $th -> signup -> stop(),
                    $th -> password -> stop(),
                    $th -> email -> stop()
                ]);
            }
        ) -> then(
            function() use($th) {
                return $th -> pdo -> stop();
            }
        ) -> then(
            function() use($th) {
                $th -> parentStop();
            }
        );
    }
    
    private function parentStop() {
        parent::stop();
    }
}

?>