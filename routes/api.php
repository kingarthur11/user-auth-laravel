<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group(['middleware' => 'cors'], function (){

    Route::prefix('user')->group(function() {

        Route::post('/login', [UserController::class, 'login']);
        Route::post('/register', [UserController::class, 'register']);

        Route::group( ['middleware' => ['auth:user-api','scopes:user'] ], function(){

            Route::get('/getall', [UserController::class, 'index']);
            Route::get('/getone/{user}', [UserController::class, 'show']);
            Route::delete('/delete/{user}', [UserController::class, 'destroy']);
            Route::put('/update', [UserController::class, 'update']);

        });
    });
});
