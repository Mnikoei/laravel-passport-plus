<?php


namespace Mnikoei\PassportPlus;

use League\OAuth2\Server\AuthorizationServer;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface;

class PassportPlus
{
    private $server;

    public function __construct(AuthorizationServer $server)
    {
        $this->server = $server;
    }

    public function createTokens($username, $password, $clientId, $clientSecret, $scopes = [])
    {
        $request = static::createRequest();

        static::setValues($request, [
            'username' => $username,
            'password' => $password,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'scope' => $scopes,
            'grant_type' => 'password'
        ]);

        $response = $this->server->respondToAccessTokenRequest($request, new Response());

        return json_decode($response->getBody()->__toString(), true);
    }

    public function refreshToken($refreshToken, $clientId, $clientSecret)
    {
        $request = static::createRequest();

        static::setValues($request, [
            'refresh_token' => $refreshToken,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'grant_type' => 'refresh_token'
        ]);

        $response = $this->server->respondToAccessTokenRequest($request, new Response());

        return json_decode($response->getBody()->__toString(), true);
    }

    public static function createRequest()
    {
        return app(ServerRequestInterface::class);
    }

    public static function setValues($request, $data)
    {
        $ref = new \ReflectionProperty(get_class($request), 'parsedBody');
        $ref->setAccessible( true );
        $ref->setValue($request, $data);
    }
}