<?php


namespace Mnikoei\PassportPlus;

use Laravel\Passport\Bridge\AccessTokenRepository as BaseAccessTokenRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class AccessTokenRepository extends BaseAccessTokenRepository
{
    public function getNewTokenWithData(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null, $customClaims = [])
    {
        return new AccessToken($userIdentifier, $scopes, $clientEntity, $customClaims);
    }
}