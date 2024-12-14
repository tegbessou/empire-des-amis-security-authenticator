<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model;

final readonly class Token
{
    public function __construct(
        public string $token,
    ) {
    }
}
