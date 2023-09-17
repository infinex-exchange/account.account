<?php

require __DIR__.'/AuthApiV2.php';

class App extends Infinex\App\Daemon {
    private $pdo;
    private $api;
    
    function __construct() {
        parent::__construct('auth.api-v2');
        
        $this -> pdo = new Infinex\Database\PDO($this -> loop, $this -> log);
        $this -> pdo -> start();
        
        $this -> api = new Infinex\API(
            $this -> log,
            'api_auth',
            new AuthApiV2($this -> log, $this -> pdo)
        );
        
        $th = $this;
        $this -> amqp -> on('connect', function() use($th) {
            $th -> api -> bind($th -> amqp);
        });
    }
}

?>