<?php

namespace Mnikoei\PassportPlus;

use Illuminate\Auth\RequestGuard;
use Illuminate\Config\Repository as Config;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportUserProvider;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;

class PassportPlusServiceProvider extends ServiceProvider
{
    public function register()
    {
        if (config('passport-plus.cache')) {

            $this->registerResourceServer();
            $this->registerGuard();
        }
    }

    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/passport-plus.php' => config_path('passport-plus.php')]
            , 'passport-plus'
        );
    }

    /**
     * Register the resource server.
     *
     * @return void
     */
    protected function registerResourceServer()
    {
        $this->app->singleton(ResourceServer::class, function () {
            return new ResourceServer(
                $this->app->make(AccessTokenRepository::class, ['tokenRepository' => new TokenRepository()]),
                $this->makeCryptKey('public')
            );
        });
    }

    /**
     * Create a CryptKey instance without permissions check.
     *
     * @param  string  $type
     * @return \League\OAuth2\Server\CryptKey
     */
    protected function makeCryptKey($type)
    {
        $key = str_replace('\\n', "\n", $this->app->make(Config::class)->get('passport.'.$type.'_key'));

        if (! $key) {
            $key = 'file://'.Passport::keyPath('oauth-'.$type.'.key');
        }

        return new CryptKey($key, null, false);
    }

    /**
     * Register the token guard.
     *
     * @return void
     */
    protected function registerGuard()
    {
        Auth::resolved(function ($auth) {
            $auth->extend('passport', function ($app, $name, array $config) {
                return tap($this->makeGuard($config), function ($guard) {
                    $this->app->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }


    /**
     * Make an instance of the token guard.
     *
     * @param  array  $config
     * @return \Illuminate\Auth\RequestGuard
     */
    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new TokenGuard(
                $this->app->make(ResourceServer::class),
                new PassportUserProvider(Auth::createUserProvider($config['provider']), $config['provider']),
                $this->app->make(TokenRepository::class),
                $this->app->make(ClientRepository::class),
                $this->app->make('encrypter')
            ))->user($request);
        }, $this->app['request']);
    }
}
