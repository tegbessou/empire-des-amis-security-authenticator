<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Tests\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator\AuthenticateUserFromProviderFirebase;
use EmpireDesAmis\SecurityAuthenticatorBundle\Security\Authenticator\FirebaseAuthenticator;
use EmpireDesAmis\SecurityAuthenticatorBundle\Services\AuthenticateUserService;
use Kreait\Firebase\Auth\SignInResult;
use Kreait\Firebase\Contract\Auth;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\Translation\TranslatorInterface;

final class FirebaseAuthenticatorTest extends TestCase
{
    private AuthenticateUserFromProviderFirebase $authenticator;

    public function setUp(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithIdpAccessToken')->willReturn(
            SignInResult::fromData([
                'email' => 'hugues.gobet@gmail.com',
            ]),
        );

        $this->authenticator = new AuthenticateUserFromProviderFirebase($auth);
    }

    public function testSupports(): void
    {
        $tokenExtractor = $this->createMock(TokenExtractorInterface::class);
        $tokenExtractor->method('extract')
            ->willReturn('token')
        ;

        $translator = $this->createMock(TranslatorInterface::class);
        $authenticateUserService = new AuthenticateUserService(
            $this->authenticator,
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
        $authenticateUserService = new AuthenticateUserService(
            $this->authenticator,
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
        $authenticateUserService = new AuthenticateUserService(
            $this->authenticator,
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
        $authenticateUserService = new AuthenticateUserService(
            $this->authenticator,
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
        $authenticateUserService = new AuthenticateUserService(
            $this->authenticator,
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
        $authenticateUserService = new AuthenticateUserService(
            $this->authenticator,
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
