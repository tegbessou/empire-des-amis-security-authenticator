<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\LogIn;

use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\Token;
use Kreait\Firebase\Contract\Auth;

final readonly class LogInFakeFirebase
{
    public function __construct(
        /** @phpstan-ignore-next-line */
        private Auth $auth,
    ) {
    }

    public function logInWithEmail(string $email, string $password): Token
    {
        return new Token(
            'eyJhbGciOiJSUzI1NiIsImtpZCI6ImYwOGU2ZTNmNzg4ZDYwMTk0MDA1ZGJiYzE5NDc0YmY5Mjg5ZDM5ZWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vcG9jL',
        );
    }
}
