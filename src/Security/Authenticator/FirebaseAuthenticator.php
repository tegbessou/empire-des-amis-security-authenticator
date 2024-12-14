<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\ExpiredTokenException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidPayloadException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidTokenException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;
use EmpireDesAmis\SecurityAuthenticatorBundle\Services\AuthenticateUserService;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationFailureResponse;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use Monolog\Attribute\WithMonologChannel;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\Translation\TranslatorInterface;

#[WithMonologChannel('security')]
final class FirebaseAuthenticator extends AbstractAuthenticator implements FirebaseAuthenticatorInterface
{
    public function __construct(
        protected readonly TokenExtractorInterface $tokenExtractor,
        protected readonly TranslatorInterface $translator,
        protected readonly LoggerInterface $logger,
        protected readonly AuthenticateUserService $authenticateUser,
    ) {
    }

    #[\Override]
    public function supports(Request $request): bool
    {
        return false !== $this->tokenExtractor->extract($request)
            && $request->headers->has(FirebaseAuthenticatorInterface::HEADER_IDENTITY_PROVIDER)
        ;
    }

    #[\Override]
    public function authenticate(Request $request): Passport
    {
        $token = $this->tokenExtractor->extract($request);

        if (false === $token || '' === $token) {
            $this->logger->error(
                'Unable to extract a JWT token from the request.',
            );

            throw new \LogicException('Unable to extract a JWT token from the request. Also, make sure to call `supports()` before `authenticate()` to get a proper client error.');
        }

        $providerId = $request->headers->get(FirebaseAuthenticatorInterface::HEADER_IDENTITY_PROVIDER);

        if (null === $providerId) {
            $this->logger->error(
                'No provider ID in request.',
            );

            throw new \LogicException('No provider ID in request.');
        }

        try {
            $userAuthenticated = $this->authenticateUser->authenticate($token, $providerId);
        } catch (InvalidTokenException $exception) {
            $this->logger->error(
                'Log in user: Invalid token',
                [
                    'exception' => $exception,
                    'provider' => $providerId,
                ],
            );

            throw new AuthenticationException($exception->getMessage());
        } catch (ExpiredTokenException $exception) {
            $this->logger->error(
                'Log in user: Token expired',
                [
                    'exception' => $exception,
                    'provider' => $providerId,
                ],
            );

            throw new AuthenticationException($exception->getMessage());
        } catch (InvalidPayloadException $exception) {
            $this->logger->error(
                'Log in user: Invalid payload',
                [
                    'exception' => $exception,
                    'provider' => $providerId,
                ],
            );

            throw new AuthenticationException($exception->getMessage());
        }

        $email = $userAuthenticated->email;

        return new SelfValidatingPassport(
            new UserBadge(
                $email,
                fn () => new User(
                    $email,
                ),
            )
        );
    }

    #[\Override]
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): null
    {
        return null;
    }

    #[\Override]
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new JWTAuthenticationFailureResponse(
            $this->translator->trans($exception->getMessageKey(), $exception->getMessageData(), 'security'),
        );
    }
}
