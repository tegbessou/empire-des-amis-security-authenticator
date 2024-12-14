<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Tests\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator\AuthenticateUserFromProviderFirebaseInterface;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Authenticator\FirebaseAuthenticator;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Model\User;
use EmpireDesAmis\SecurityAuthenticatorBundle\Service\AuthenticateUserService;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\Translation\TranslatorInterface;

final class FirebaseAuthenticatorTest extends TestCase
{
    public function testSupports(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn('token')
        ;

        $translator = $this->createMock(TranslatorInterface::class);

        $authenticator = $this->createMock(AuthenticateUserFromProviderFirebaseInterface::class);

        $authenticateUserService = new AuthenticateUserService(
            $authenticator,
            new EventDispatcher(),
        );

        $authenticator = new FirebaseAuthenticator(
            $tokenExtractor,
            $translator,
            new NullLogger(),
            $authenticateUserService,
        );

        $request = Request::create(
            uri: '/',
        );
        $request->headers->set('RequestHeaderIdentityProvider', 'google.com');

        $this->assertTrue(
            $authenticator->supports($request),
        );
    }

    public function testSupportsFailedInvalidToken(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn(false)
        ;

        $translator = $this->createMock(TranslatorInterface::class);

        $authenticator = $this->createMock(AuthenticateUserFromProviderFirebaseInterface::class);

        $authenticateUserService = new AuthenticateUserService(
            $authenticator,
            new EventDispatcher(),
        );

        $authenticator = new FirebaseAuthenticator(
            $tokenExtractor,
            $translator,
            new NullLogger(),
            $authenticateUserService,
        );

        $request = Request::create(
            uri: '/',
        );
        $request->headers->set('RequestHeaderIdentityProvider', 'google.com');

        $this->assertFalse(
            $authenticator->supports($request),
        );
    }

    public function testSupportsFailedInvalidNoHeader(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn('token')
        ;

        $translator = $this->createMock(TranslatorInterface::class);

        $authenticator = $this->createMock(AuthenticateUserFromProviderFirebaseInterface::class);

        $authenticateUserService = new AuthenticateUserService(
            $authenticator,
            new EventDispatcher(),
        );

        $authenticator = new FirebaseAuthenticator(
            $tokenExtractor,
            $translator,
            new NullLogger(),
            $authenticateUserService,
        );

        $request = Request::create(
            uri: '/',
        );

        $this->assertFalse(
            $authenticator->supports($request),
        );
    }

    public function testAuthenticate(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn('token')
        ;

        $translator = $this->createMock(TranslatorInterface::class);

        $authenticator = $this->createMock(AuthenticateUserFromProviderFirebaseInterface::class);
        $authenticator->method('authenticateUserWithGoogle')
            ->willReturn(
                new User('hugues.gobet@gmail.com'),
            )
        ;

        $authenticateUserService = new AuthenticateUserService(
            $authenticator,
            new EventDispatcher(),
        );

        $authenticator = new FirebaseAuthenticator(
            $tokenExtractor,
            $translator,
            new NullLogger(),
            $authenticateUserService,
        );

        $request = Request::create(
            uri: '/',
        );
        $request->headers->set('RequestHeaderIdentityProvider', 'google.com');

        $passport = $authenticator->authenticate($request);
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
        $this->assertSame('hugues.gobet@gmail.com', $passport->getUser()->getUserIdentifier());
    }

    public function testAuthenticateUnableToExtractToken(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn('')
        ;

        $translator = $this->createMock(TranslatorInterface::class);

        $authenticator = $this->createMock(AuthenticateUserFromProviderFirebaseInterface::class);
        $authenticateUserService = new AuthenticateUserService(
            $authenticator,
            new EventDispatcher(),
        );

        $authenticator = new FirebaseAuthenticator(
            $tokenExtractor,
            $translator,
            new NullLogger(),
            $authenticateUserService,
        );

        $request = Request::create(
            uri: '/',
        );
        $request->headers->set('RequestHeaderIdentityProvider', 'google.com');

        $this->expectException(\LogicException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateNoProviderId(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn('token')
        ;

        $translator = $this->createMock(TranslatorInterface::class);

        $authenticator = $this->createMock(AuthenticateUserFromProviderFirebaseInterface::class);

        $authenticateUserService = new AuthenticateUserService(
            $authenticator,
            new EventDispatcher(),
        );

        $authenticator = new FirebaseAuthenticator(
            $tokenExtractor,
            $translator,
            new NullLogger(),
            $authenticateUserService,
        );

        $request = Request::create(
            uri: '/',
        );

        $this->expectException(\LogicException::class);
        $authenticator->authenticate($request);
    }
}
