<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Security\Service;

use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User as SymfonyUser;
use Symfony\Bundle\SecurityBundle\Security;

final readonly class GetUserAuthenticatedService
{
    public function __construct(
        private Security $security,
    ) {
    }

    public function getUser(): User
    {
        /** @var SymfonyUser|null $user */
        $user = $this->security->getUser();

        if (null === $user) {
            throw new \LogicException();
        }

        return new User(
            $user->email,
        );
    }
}
