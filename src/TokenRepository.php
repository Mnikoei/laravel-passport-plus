<?php

namespace Mnikoei\PassportPlus;

use Illuminate\Support\Facades\Cache;
use Laravel\Passport\TokenRepository as BaseTokenRepository;

class TokenRepository extends BaseTokenRepository
{
    /**
     * Get a token by the given ID.
     *
     * @param  string  $id
     * @return \Laravel\Passport\Token
     */
    public function find($id)
    {
        $ttl = config('passport-plus.cache-ttl');

        return Cache::tags('passport-plus')->remember("token-$id", $ttl ?: 60, function () use ($id) {

            return parent::find($id);
        });
    }

    /**
     * Revoke an access token.
     *
     * @param  string  $id
     * @return mixed
     */
    public function revokeAccessToken($id)
    {
        Cache::tags('passport-plus')->forget("token-$id");

        return parent::revokeAccessToken($id);
    }
}
