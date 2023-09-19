<?php

require __DIR__.'/MFA.php';
require __DIR__.'/SignupAPI.php';
require __DIR__.'/SessionsApiKeysAPI.php';

class App extends Infinex\App\Daemon {
    private $pdo;
    private $mfa;
    private $api;
    
    function __construct() {
        parent::__construct('auth.api-v2');
        
        $this -> pdo = new Infinex\Database\PDO($this -> loop, $this -> log);
        $this -> pdo -> start();
        
        $this -> mfa = new MFA($this -> log, $this -> amqp, $this -> pdo);
        
        $this -> api = new Infinex\API(
            $this -> log,
            'api_auth',
            [
                new SignupAPI(
                    $this -> log,
                    $this -> amqp,
                    $this -> pdo
                ),
                new SessionsApiKeysAPI(
                    $this -> log,
                    $this -> amqp,
                    $this -> pdo,
                    $this -> mfa
                )
            ]
        );
        
        $th = $this;
        $this -> amqp -> on('connect', function() use($th) {
            $th -> api -> bind($th -> amqp);
        });
    }
}

?>