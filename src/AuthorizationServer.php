<?php


namespace Mnikoei\PassportPlus;

use League\OAuth2\Server\AuthorizationServer as BaseAuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;

class AuthorizationServer extends BaseAuthorizationServer
{
    public function __construct(ClientRepositoryInterface $clientRepository, AccessTokenRepositoryInterface $accessTokenRepository, ScopeRepositoryInterface $scopeRepository, $privateKey, $encryptionKey, ResponseTypeInterface $responseType = null)
    {
        parent::__construct(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey,
            $responseType
        );

        if ($responseType === null) {
            $responseType = new BearerTokenResponse();
        } else {
            $responseType = clone $responseType;
        }

        $this->responseType = $responseType;
    }
}