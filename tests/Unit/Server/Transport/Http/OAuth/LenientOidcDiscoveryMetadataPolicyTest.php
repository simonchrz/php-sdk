<?php

/*
 * This file is part of the official PHP MCP SDK.
 *
 * A collaboration between Symfony and the PHP Foundation.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mcp\Tests\Unit\Server\Transport\Http\OAuth;

use Mcp\Server\Transport\Http\OAuth\LenientOidcDiscoveryMetadataPolicy;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;

/**
 * Tests LenientOidcDiscoveryMetadataPolicy validation behavior.
 */
class LenientOidcDiscoveryMetadataPolicyTest extends TestCase
{
    #[TestDox('metadata without code challenge methods is valid in lenient mode')]
    public function testMissingCodeChallengeMethodsIsValid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();
        $metadata = [
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint' => 'https://auth.example.com/token',
            'jwks_uri' => 'https://auth.example.com/jwks',
        ];

        $this->assertTrue($policy->isValid($metadata));
    }

    #[TestDox('metadata with code challenge methods is also valid in lenient mode')]
    public function testWithCodeChallengeMethodsIsValid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();
        $metadata = [
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint' => 'https://auth.example.com/token',
            'jwks_uri' => 'https://auth.example.com/jwks',
            'code_challenge_methods_supported' => ['S256'],
        ];

        $this->assertTrue($policy->isValid($metadata));
    }

    #[TestDox('metadata missing authorization endpoint is invalid')]
    public function testMissingAuthorizationEndpointIsInvalid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();
        $metadata = [
            'token_endpoint' => 'https://auth.example.com/token',
            'jwks_uri' => 'https://auth.example.com/jwks',
        ];

        $this->assertFalse($policy->isValid($metadata));
    }

    #[TestDox('metadata missing token endpoint is invalid')]
    public function testMissingTokenEndpointIsInvalid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();
        $metadata = [
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'jwks_uri' => 'https://auth.example.com/jwks',
        ];

        $this->assertFalse($policy->isValid($metadata));
    }

    #[TestDox('metadata missing jwks uri is invalid')]
    public function testMissingJwksUriIsInvalid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();
        $metadata = [
            'authorization_endpoint' => 'https://auth.example.com/authorize',
            'token_endpoint' => 'https://auth.example.com/token',
        ];

        $this->assertFalse($policy->isValid($metadata));
    }

    #[TestDox('empty endpoint strings are invalid')]
    public function testEmptyEndpointStringsAreInvalid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();
        $metadata = [
            'authorization_endpoint' => '',
            'token_endpoint' => 'https://auth.example.com/token',
            'jwks_uri' => 'https://auth.example.com/jwks',
        ];

        $this->assertFalse($policy->isValid($metadata));
    }

    #[TestDox('non array metadata is invalid')]
    public function testNonArrayMetadataIsInvalid(): void
    {
        $policy = new LenientOidcDiscoveryMetadataPolicy();

        $this->assertFalse($policy->isValid('not an array'));
    }
}
