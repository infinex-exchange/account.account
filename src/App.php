<?php

require __DIR__.'/Users.php';
require __DIR__.'/Sessions.php';
require __DIR__.'/MFA.php';

require __DIR__.'/API/MFAAPI.php';
require __DIR__.'/API/SessionsAPI.php';
require __DIR__.'/API/SignupAPI.php';
require __DIR__.'/API/PasswordAPI.php';
require __DIR__.'/API/EmailAPI.php';

use React\Promise;

class App extends Infinex\App\App {
    private $pdo;
    
    private $users;
    private $sessions;
    private $mfa;
    
    private $mfaApi;
    private $sessionsApi;
    private $signupApi;
    private $passwordApi;
    private $emailApi;
    private $rest;
    
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
        
        $this -> mfaApi = new MFAAPI(
            $this -> log,
            $this -> pdo,
            $this -> mfa
        );
        
        $this -> sessionsApi = new SessionsAPI(
            $this -> log,
            $this -> pdo,
            $this -> mfa
        );
        
        $this -> signupApi = new SignupAPI(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
        
        $this -> passwordApi = new PasswordAPI(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
        
        $this -> emailApi = new EmailAPI(
            $this -> log,
            $this -> amqp,
            $this -> pdo
        );
        
        $this -> rest = new Infinex\API\REST(
            $this -> log,
            $this -> amqp,
            [
                $this -> mfaApi,
                $this -> sessionsApi,
                $this -> signupApi,
                $this -> passwordApi,
                $this -> emailApi
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
                return Promise\all([
                    $th -> users -> start(),
                    $th -> sessions -> start(),
                    $th -> mfa -> start()
                ]);
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
                return Promise\all([
                    $th -> users -> stop(),
                    $th -> sessions -> stop(),
                    $th -> mfa -> stop()
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