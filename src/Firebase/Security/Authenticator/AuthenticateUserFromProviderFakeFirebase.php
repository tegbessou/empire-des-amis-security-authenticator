<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;
use Kreait\Firebase\Contract\Auth;

final readonly class AuthenticateUserFromProviderFakeFirebase
{
    public function __construct(
        /** @phpstan-ignore-next-line */
        private Auth $auth,
    ) {
    }

    public function authenticateUserWithApple(string $token): User
    {
        if ('tokenusernotexist' === $token) {
            return new User('nexistepas@gmail.com');
        }

        return new User('hugues.gobet@gmail.com');
    }

    public function authenticateUserWithGoogle(string $token): User
    {
        return new User('hugues.gobet@gmail.com');
    }

    public function authenticateUserWithFirebase(string $token): User
    {
        return new User('services.tasting@gmail.com');
    }
}
