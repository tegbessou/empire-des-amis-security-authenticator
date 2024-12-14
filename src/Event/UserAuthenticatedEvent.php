<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Event;

final readonly class UserAuthenticatedEvent
{
    public function __construct(
        public string $email,
    ) {
    }
}
