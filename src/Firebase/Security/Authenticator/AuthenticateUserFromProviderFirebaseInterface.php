<?php

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;

interface AuthenticateUserFromProviderFirebaseInterface
{
    public function authenticateUserWithApple(string $token): User;

    public function authenticateUserWithGoogle(string $token): User;

    public function authenticateUserWithFirebase(string $token): User;
}
