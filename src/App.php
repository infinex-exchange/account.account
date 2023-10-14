<?php

require __DIR__.'/VeriCodes.php';
require __DIR__.'/Users.php';
require __DIR__.'/Sessions.php';

require __DIR__.'/API/SignupAPI.php';
require __DIR__.'/API/EmailAPI.php';
require __DIR__.'/API/PasswordAPI.php';
require __DIR__.'/API/SessionsAPI.php';

use React\Promise;

class App extends Infinex\App\App {
    private $pdo;
    
    private $vc;
    private $users;
    private $sessions;
    
    private $signupApi;
    private $emailApi;
    private $passwordApi;
    private $sessionsApi;
    private $rest;
    
    function __construct() {
        parent::__construct('account.account');
        
        $this -> pdo = new Infinex\Database\PDO(
            $this -> loop,
            $this -> log,
            DB_HOST,
            DB_USER,
            DB_PASS,
            DB_NAME
        );
        
        $this -> vc = new VeriCodes(
            $this -> log,
            $this -> pdo
        );
        
        $this -> users = new Users(
            $this -> log,
            $this -> amqp,
            $this -> pdo,
            $this -> vc
        );
        
        $this -> sessions = new Sessions(
            $this -> log,
            $this -> amqp,
            $this -> pdo,
            $this -> users
        );
        
        $this -> signupApi = new SignupAPI(
            $this -> log,
            $this -> pdo,
            $this -> users,
            $this -> vc
        );
        
        $this -> emailApi = new EmailAPI(
            $this -> log,
            $this -> amqp,
            $this -> pdo,
            $this -> users,
            $this -> vc
        );
        
        $this -> passwordApi = new PasswordAPI(
            $this -> log,
            $this -> amqp,
            $this -> pdo,
            $this -> users,
            $this -> vc
        );
        
        $this -> sessionsApi = new SessionsAPI(
            $this -> log,
            $this -> amqp,
            $this -> sessions,
            $this -> users
        );
        
        $this -> rest = new Infinex\API\REST(
            $this -> log,
            $this -> amqp,
            [
                $this -> signupApi,
                $this -> emailApi,
                $this -> passwordApi,
                $this -> sessionsApi
            ]
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
                return $th -> vc -> start();
            }
        ) -> then(
            function() use($th) {
                return $th -> users -> start();
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
                return $th -> users -> stop();
            }
        ) -> then(
            function() use($th) {
                return $th -> vc -> stop();
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