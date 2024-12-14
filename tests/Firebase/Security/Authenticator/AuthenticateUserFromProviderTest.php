<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Tests\Firebase\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\ExpiredTokenException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidPayloadException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\Authenticator\AuthenticateUserFromProviderFirebase;
use Kreait\Firebase\Auth\SignIn\FailedToSignIn;
use Kreait\Firebase\Auth\SignInResult;
use Kreait\Firebase\Contract\Auth;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\InvalidTokenException;
use PHPUnit\Framework\TestCase;

final class AuthenticateUserFromProviderTest extends TestCase
{
    public function testAuthenticateUserWithApple(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willReturn(
            new Plain(
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new DataSet(
                    [
                        'email' => 'hugues.gobet@gmail.com',
                    ],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new Signature(
                    'fakehash',
                    'qVWPTgmg4ks3TDjcsNGx4iXSe2nmloTl6tJk2RjUHME',
                ),
            ),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $user = $authenticator->authenticateUserWithApple('token');

        $this->assertEquals(
            'hugues.gobet@gmail.com',
            $user->email,
        );
    }

    public function testAuthenticateUserWithAppleEmptyToken(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(\InvalidArgumentException::class);

        $authenticator->authenticateUserWithApple('');
    }

    public function testAuthenticateUserWithAppleFailedToSignIn(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(InvalidTokenException::class);

        $authenticator->authenticateUserWithApple('token');
    }

    public function testAuthenticateUserWithAppleIsExpired(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willReturn(
            new Plain(
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new DataSet(
                    [
                        'email' => 'hugues.gobet@gmail.com',
                        'exp' => '1734033527',
                    ],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new Signature(
                    'fakehash',
                    'qVWPTgmg4ks3TDjcsNGx4iXSe2nmloTl6tJk2RjUHME',
                ),
            ),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(ExpiredTokenException::class);

        $authenticator->authenticateUserWithApple('token');
    }

    public function testAuthenticateUserWithAppleNoEmail(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willReturn(
            new Plain(
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new Signature(
                    'fakehash',
                    'qVWPTgmg4ks3TDjcsNGx4iXSe2nmloTl6tJk2RjUHME',
                ),
            ),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(InvalidPayloadException::class);

        $authenticator->authenticateUserWithApple('token');
    }

    public function testAuthenticateUserWithGoogle(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithIdpAccessToken')->willReturn(
            SignInResult::fromData([
                'email' => 'hugues.gobet@gmail.com',
            ]),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $user = $authenticator->authenticateUserWithGoogle('token');

        $this->assertEquals(
            'hugues.gobet@gmail.com',
            $user->email,
        );
    }

    public function testAuthenticateUserWithGoogleEmptyToken(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithIdpAccessToken')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(\InvalidArgumentException::class);

        $authenticator->authenticateUserWithGoogle('');
    }

    public function testAuthenticateUserWithGoogleFailedSignIn(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithIdpAccessToken')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(InvalidTokenException::class);

        $authenticator->authenticateUserWithGoogle('token');
    }

    public function testAuthenticateUserWithGoogleNoEmail(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithIdpAccessToken')->willReturn(
            SignInResult::fromData([]),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(InvalidPayloadException::class);

        $authenticator->authenticateUserWithGoogle('token');
    }

    public function testAuthenticateUserWithFirebase(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willReturn(
            new Plain(
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new DataSet(
                    [
                        'email' => 'hugues.gobet@gmail.com',
                    ],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new Signature(
                    'fakehash',
                    'qVWPTgmg4ks3TDjcsNGx4iXSe2nmloTl6tJk2RjUHME',
                ),
            ),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $user = $authenticator->authenticateUserWithFirebase('token');

        $this->assertEquals(
            'hugues.gobet@gmail.com',
            $user->email,
        );
    }

    public function testAuthenticateUserWithFirebaseEmptyToken(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(\InvalidArgumentException::class);

        $authenticator->authenticateUserWithFirebase('');
    }

    public function testAuthenticateUserWithFirebaseFailedToSignIn(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(InvalidTokenException::class);

        $authenticator->authenticateUserWithFirebase('token');
    }

    public function testAuthenticateUserWithFirebaseNoEmail(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('parseToken')->willReturn(
            new Plain(
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new DataSet(
                    [],
                    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                ),
                new Signature(
                    'fakehash',
                    'qVWPTgmg4ks3TDjcsNGx4iXSe2nmloTl6tJk2RjUHME',
                ),
            ),
        );

        $authenticator = new AuthenticateUserFromProviderFirebase($auth);

        $this->expectException(InvalidPayloadException::class);

        $authenticator->authenticateUserWithFirebase('token');
    }
}
