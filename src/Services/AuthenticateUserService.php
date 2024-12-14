<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Services;

use EmpireDesAmis\SecurityAuthenticatorBundle\Event\UserAuthenticatedEvent;
use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\IdentityProviderDoesntExistException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidTokenException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator\AuthenticateUserFromProviderFirebase;
use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Enum\ProviderEnum;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class AuthenticateUserService
{
    public function __construct(
        private AuthenticateUserFromProviderFirebase $authenticateUserFromProvider,
        private EventDispatcherInterface $dispatcher,
    ) {
    }

    public function authenticate(string $token, string $providerId): User
    {
        if ('' === $token) {
            throw new InvalidTokenException();
        }

        $userAuthenticated = $this->authenticateUserFromProvider(
            $token,
            $providerId,
        );

        $this->dispatcher->dispatch(new UserAuthenticatedEvent(
            $userAuthenticated->getUserIdentifier(),
        ));

        return $userAuthenticated;
    }

    private function authenticateUserFromProvider(string $token, string $providerId): User
    {
        match ($providerId) {
            ProviderEnum::IDENTITY_PROVIDER_APPLE->value => $userAuthenticated = $this->authenticateUserFromProvider->authenticateUserWithApple($token),
            ProviderEnum::IDENTITY_PROVIDER_GOOGLE->value => $userAuthenticated = $this->authenticateUserFromProvider->authenticateUserWithGoogle($token),
            ProviderEnum::IDENTITY_PROVIDER_FIREBASE->value => $userAuthenticated = $this->authenticateUserFromProvider->authenticateUserWithFirebase($token),
            default => throw new IdentityProviderDoesntExistException('Invalid provider id'),
        };

        return $userAuthenticated;
    }
}
