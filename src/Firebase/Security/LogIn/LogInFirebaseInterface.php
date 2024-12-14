<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\LogIn;

use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\Token;

interface LogInFirebaseInterface
{
    public function logInWithEmail(string $email, string $password): Token;
}
