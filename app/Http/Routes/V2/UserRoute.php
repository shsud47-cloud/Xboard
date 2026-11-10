<?php
namespace App\Http\Routes\V2;

use App\Http\Controllers\V1\User\PasskeyController;
use App\Http\Controllers\V1\User\UserController;
use Illuminate\Contracts\Routing\Registrar;

class UserRoute
{
    public function map(Registrar $router)
    {
        $router->group([
            'prefix' => 'user',
            'middleware' => 'user'
        ], function ($router) {
            // User
            $router->get('/resetSecurity', [UserController::class, 'resetSecurity']);
            $router->get('/info', [UserController::class, 'info']);
            $router->get('/passkey', [PasskeyController::class, 'index']);
            $router->post('/passkey/options', [PasskeyController::class, 'options']);
            $router->post('/passkey/register', [PasskeyController::class, 'register']);
            $router->post('/passkey/delete', [PasskeyController::class, 'delete']);
        });
    }
}
