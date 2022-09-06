<?php

namespace Gentor\OAuth1Etsy\Client\Server;

use Gentor\OAuth1Etsy\Client\Signature\HmacSha1Signature;
use GuzzleHttp\Exception\BadResponseException;
use League\OAuth1\Client\Server\Server;
use League\OAuth1\Client\Credentials;
use League\OAuth1\Client\Server\User;
use League\OAuth1\Client\Credentials\TemporaryCredentials;
use League\OAuth1\Client\Credentials\TokenCredentials;
use League\OAuth1\Client\Signature\SignatureInterface;
use League\OAuth1\Client\Signature\HmacSha1Signature as LeagueHmacSha1Signature;

class Etsy extends Server
{
    const API_URL = 'https://openapi.etsy.com/v2/';

    /**
     * Application scope.
     *
     * @var string
     */
    protected $applicationScope = "";

    /**
     * Login url for authorization provided by Etsy
     * @var string
     */
    protected $login_url = "";


    /**
     * {@inheritDoc}
     */
    public function __construct($clientCredentials, SignatureInterface $signature = null)
    {
        parent::__construct($clientCredentials, $signature);

        if (is_array($clientCredentials)) {
            $this->parseConfiguration($clientCredentials);
        }

        if ($this->signature instanceof LeagueHmacSha1Signature) {
            $this->signature = new HmacSha1Signature($this->clientCredentials);
        }
    }

    /**
     * Set the application scope.
     *
     * @param string $applicationScope
     *
     * @return Etsy
     */
    public function setApplicationScope($applicationScope)
    {
        $this->applicationScope = $applicationScope;
        return $this;
    }

    /**
     * Get application scope.
     *
     * @return string
     */
    public function getApplicationScope()
    {
        return $this->applicationScope;
    }

    /**
     * {@inheritDoc}
     */
    public function urlTemporaryCredentials(): string
    {
        return self::API_URL . 'oauth/request_token?scope=' . $this->applicationScope;
    }

    /**
     * {@inheritDoc}
     */
    public function urlAuthorization(): string
    {
        return $this->login_url;
    }

    /**
     * {@inheritDoc}
     */
    public function urlTokenCredentials(): string
    {
        return self::API_URL . 'oauth/access_token';
    }

    /**
     * {@inheritDoc}
     */
    public function urlUserDetails(): string
    {
        return self::API_URL . 'users/__SELF__';
    }

    /**
     * {@inheritDoc}
     */
    public function userDetails($data, TokenCredentials $tokenCredentials): User
    {
        $data = $data['results'][0];

        $user = new User();
        $user->uid = $data['user_id'];
        $user->nickname = $data['login_name'];

        $used = array('user_id', 'login_name');

        // Save all extra data
        $user->extra = array_diff_key($data, array_flip($used));
        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function userUid($data, TokenCredentials $tokenCredentials)
    {
        return $data['user']['user_id'];
    }

    /**
     * {@inheritDoc}
     */
    public function userEmail($data, TokenCredentials $tokenCredentials): ?string
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public function userScreenName($data, TokenCredentials $tokenCredentials): ?string
    {
        return $data['user']['login_name'];
    }

    /**
     * Parse configuration array to set attributes.
     *
     * @param array $configuration
     */
    private function parseConfiguration(array $configuration = array())
    {
        $configToPropertyMap = array(
            'scope' => 'applicationScope'
        );

        foreach ($configToPropertyMap as $config => $property) {
            if (isset($configuration[$config])) {
                $this->$property = $configuration[$config];
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getTemporaryCredentials(): TemporaryCredentials
    {
        $uri = $this->urlTemporaryCredentials();

        $client = $this->createHttpClient();

        $header = $this->temporaryCredentialsProtocolHeader($uri);
        $authorizationHeader = array('Authorization' => $header);
        $headers = $this->buildHttpClientHeaders($authorizationHeader);

        try {
            $response = $client->post($uri, [
                'headers' => $headers
            ]);
        } catch (BadResponseException $e) {
            $this->handleTemporaryCredentialsBadResponse($e);
            return null;
        }

        // Catch body and retrieve Etsy login_url
        $body = $response->getBody();
        parse_str($body, $data);

        $this->login_url = $data['login_url'];

        return $this->createTemporaryCredentials($response->getBody());
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($temporaryIdentifier): string
    {
        // Return the authorization url directly since it's provided by Etsy and contains all parameters
        return $this->urlAuthorization();
    }
}
