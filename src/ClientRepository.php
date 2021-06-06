<?php


namespace Mnikoei\PassportPlus;


use Illuminate\Support\Facades\Cache;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository as BaseClientRepository;

class ClientRepository extends BaseClientRepository
{
    public function find($id)
    {
        $ttl = config('passport-plus.cache-ttl');

        return Cache::tags('passport-plus')->remember("client-$id", $ttl ?: 60, function () use ($id) {
            return parent::find($id);
        });
    }

    public function update(Client $client, $name, $redirect)
    {
        Cache::tags('passport-plus')->forget("client-{$client->id}");
            
        return parent::update($client, $name, $redirect);
    }

    public function regenerateSecret(Client $client)
    {
        Cache::tags('passport-plus')->forget("client-{$client->id}");
        
        return parent::regenerateSecret($client);
    }

    public function revoked($id)
    {
        Cache::tags('passport-plus')->forget("client-$id");

        return parent::revoked($id);
    }
}