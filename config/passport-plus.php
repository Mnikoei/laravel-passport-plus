<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Caching data
    |--------------------------------------------------------------------------
    |
    | This option determines if user and token data should be read from
    | cache or not, if set true it uses customized version of passport
    | token guard and repositories that are cache based
    |
    */
    'cache' => true,

    /*
    |--------------------------------------------------------------------------
    | Cache TTL
    |--------------------------------------------------------------------------
    |
    | This options defines how long data should be kept in cache
    |
    */
    'cache-ttl' => 60

];