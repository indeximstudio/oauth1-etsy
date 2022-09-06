<?php

namespace Gentor\OAuth1Etsy\Client\Signature;

use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\UriInterface;
use League\OAuth1\Client\Signature\HmacSha1Signature as Signature;

class HmacSha1Signature extends Signature
{
    /**
     * Generate a base string for a HMAC-SHA1 signature
     * based on the given a url, method, and any parameters.
     *
     * @param UriInterface $url
     * @param string $method
     * @param array $parameters
     *
     * @return string
     */
    protected function baseString(UriInterface $url, $method = 'POST', array $parameters = array())
    {
        $baseString = rawurlencode($method) . '&';

        $schemeHostPath = Uri::fromParts(array(
            'scheme' => $url->getScheme(),
            'host' => $url->getHost(),
            'path' => $url->getPath(),
        ));

        $baseString .= rawurlencode($schemeHostPath) . '&';

        $data = array();
        $query = $this->parseQuery($url->getQuery());
        foreach (array_merge($query, $parameters) as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $subValue) {
                    $data[] = array(rawurlencode($key), rawurlencode($subValue));
                }
            } else {
                $data[] = array(rawurlencode($key), rawurlencode($value));
            }
        }

        // compare only the keys
        usort($data, function ($a, $b) {
            return strcmp($a[0], $b[0]);
        });

        foreach ($data as $key => $pair) {
            $data[$key] = sprintf('%s=%s', $pair[0], $pair[1]);
        }

        $baseString .= rawurlencode(implode('&', $data));

        return $baseString;
    }

    /**
     * Parses a query string into components including properly parsing queries that have array in them like a[]=1
     * or a[hello]=1.
     *
     * @param string $query The query string to parse into an associative array.
     *
     * @return array The parsed query into a single-level associative array.
     */
    protected function parseQuery($query)
    {
        $parsed = array();
        $parts = explode('&', $query);

        foreach ($parts as $part) {
            $equalsPos = strpos($part, '=');

            if ($equalsPos === false) {
                $key = urldecode($part);
                $value = '';
            } else {
                $key = urldecode(substr($part, 0, $equalsPos));
                $value = urldecode(substr($part, $equalsPos + 1));
            }

            //Example where the key for 'c' is '': a=b&=c
            if ($key == '') {
                continue;
            }

            if (!isset($parsed[$key])) {
                $parsed[$key] = $value;
            } else {
                //ensure this is an array since we need to store multiple values
                if (!is_array($parsed[$key])) {
                    $parsed[$key] = array($parsed[$key]);
                }

                $parsed[$key][] = $value;
            }
        }

        return $parsed;
    }
}
