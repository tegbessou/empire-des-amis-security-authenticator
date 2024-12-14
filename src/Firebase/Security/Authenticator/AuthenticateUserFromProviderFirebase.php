<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\ExpiredTokenException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidPayloadException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Enum\ProviderEnum;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;
use Kreait\Firebase\Auth\SignIn\FailedToSignIn;
use Kreait\Firebase\Contract\Auth;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\InvalidTokenException;

final readonly class AuthenticateUserFromProviderFirebase implements AuthenticateUserFromProviderFirebaseInterface
{
    public function __construct(
        private Auth $auth,
    ) {
    }

    public function authenticateUserWithApple(string $token): User
    {
        if ('' === $token) {
            throw new \InvalidArgumentException('Token shouldn\'t be empty string');
        }

        try {
            $payload = $this->auth->parseToken(
                $token,
            );

            if ($payload->isExpired(new \DateTime())) {
                throw new ExpiredTokenException();
            }
        } catch (FailedToSignIn) {
            throw new InvalidTokenException();
        }

        $email = $payload->claims()->get('email');

        if (null === $email) {
            throw new InvalidPayloadException();
        }

        $email = $payload->claims()->get('email');

        if (!is_string($email)) {
            throw new InvalidPayloadException();
        }

        return new User($email);
    }

    public function authenticateUserWithGoogle(string $token): User
    {
        if ('' === $token) {
            throw new \InvalidArgumentException('Token shouldn\'t be empty string');
        }

        try {
            $payload = $this->auth->signInWithIdpAccessToken(ProviderEnum::IDENTITY_PROVIDER_GOOGLE->value, $token);
        } catch (FailedToSignIn) {
            throw new InvalidTokenException();
        }

        if (!isset($payload->data()['email'])) {
            throw new InvalidPayloadException('');
        }

        $email = $payload->data()['email'];

        if (!is_string($email)) {
            throw new InvalidPayloadException();
        }

        return new User($email);
    }

    public function authenticateUserWithFirebase(string $token): User
    {
        if ('' === $token) {
            throw new \InvalidArgumentException('Token shouldn\'t be empty string');
        }

        try {
            $payload = $this->auth->parseToken($token);
        } catch (FailedToSignIn) {
            throw new InvalidTokenException();
        }

        if (!$payload->claims()->has('email')) {
            throw new InvalidPayloadException('');
        }

        $email = $payload->claims()->get('email');

        if (!is_string($email)) {
            throw new InvalidPayloadException();
        }

        return new User($email);
    }
}
