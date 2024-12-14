<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\LogIn;

use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidPayloadException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\Token;
use Kreait\Firebase\Auth\SignIn\FailedToSignIn;
use Kreait\Firebase\Contract\Auth;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\InvalidTokenException;

final readonly class LogInFirebase
{
    public function __construct(
        private Auth $auth,
    ) {
    }

    public function logInWithEmail(string $email, string $password): Token
    {
        if ('' === $email) {
            throw new \InvalidArgumentException();
        }

        if ('' === $password) {
            throw new \InvalidArgumentException();
        }

        try {
            $payload = $this->auth->signInWithEmailAndPassword(
                $email,
                $password,
            );
        } catch (FailedToSignIn) {
            throw new InvalidTokenException();
        }

        if (!isset($payload->data()['idToken'])) {
            throw new InvalidPayloadException('');
        }

        $token = $payload->data()['idToken'];

        if (!is_string($token)) {
            throw new InvalidPayloadException();
        }

        return new Token(
            $token,
        );
    }
}
