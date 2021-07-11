<?php

namespace Mnikoei\PassportPlus;

use Laravel\Passport\Exceptions\InvalidAuthTokenException;
use Lcobucci\JWT\SodiumBase64Polyfill;
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

    public function createTokens($username, $password, $clientId, $clientSecret, array $scopes = [], array $customData = [])
    {
        $request = static::createRequest();

        static::setValues($request, [
            'username' => $username,
            'password' => $password,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'scope' => $scopes,
            'grant_type' => 'password',
            'custom_data' => $customData
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

    /**
     * @param string $token
     * @return array|mixed
     * @throws InvalidAuthTokenException
     */
    public function getCustomClaims(string $token)
    {
        try {

            $encodedClaims = explode('.', $token)[1];

            $jsonData = SodiumBase64Polyfill::base642bin(
                $encodedClaims,
                SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
            );

        }catch (\Throwable $e) {

            throw new InvalidAuthTokenException('Token is invalid!');
        }

        return json_decode($jsonData)->custom_data ?? [];
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