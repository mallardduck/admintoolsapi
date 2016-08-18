<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the controller to call when that URI is requested.
|
*/

Route::group(['domain' => 'ip.liquidweb.dev', 'as' => 'ip::'], function () {
    Route::get('/', ['as' => 'home', 'uses' => 'IpController@index']);
    Route::get('/ip', ['as' => 'ip', 'uses' => 'IpController@index']);
    Route::get('/ip.json', ['as' => 'ipJson', 'uses' => 'IpController@index']);
});

Route::group(['domain' => 'sslcheck.liquidweb.dev', 'as' => 'ssl::'], function () {
    Route::get('/', ['as' => 'home', 'uses' => 'SslController@index']);
    Route::get('/sslcheck', ['as' => 'check', 'uses' => 'SslController@index']);
    Route::get('/sslcheck.json', ['as' => 'checkjson', 'uses' => 'SslController@indexJson']);
});

Route::group(['as' => 'main::'], function () {
  Route::get('/', ['as' => 'home', 'uses' => 'IpController@index']);
  Route::get('/ip', ['as' => 'ip', 'uses' => 'IpController@index']);
  Route::get('/ip.json', ['as' => 'ipJson', 'uses' => 'IpController@index']);
  Route::get('/sslcheck', ['as' => 'check', 'uses' => 'SslController@index']);
  Route::get('/sslcheck.json', ['as' => 'checkJson', 'uses' => 'SslController@indexJson']);
});
