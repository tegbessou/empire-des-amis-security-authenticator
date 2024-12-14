<?php

declare(strict_types=1);

namespace EmpireDesAmis\SecurityAuthenticatorBundle\Tests\Firebase\Security\Authenticator;

use EmpireDesAmis\SecurityAuthenticatorBundle\Exception\InvalidPayloadException;
use EmpireDesAmis\SecurityAuthenticatorBundle\Firebase\Security\LogIn\LogInFirebase;
use Kreait\Firebase\Auth\SignIn\FailedToSignIn;
use Kreait\Firebase\Auth\SignInResult;
use Kreait\Firebase\Contract\Auth;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\InvalidTokenException;
use PHPUnit\Framework\TestCase;

final class LogInFirebaseTest extends TestCase
{
    public function testLogInWithEmail(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithEmailAndPassword')->willReturn(
            SignInResult::fromData([
                'idToken' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            ]),
        );

        $authenticator = new LogInFirebase($auth);

        $token = $authenticator->logInWithEmail('hugues.gobet@gmail.com', 'password');

        $this->assertEquals(
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            $token->token,
        );
    }

    public function testLogInWithEmailFailedToSignIn(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithEmailAndPassword')->willThrowException(
            new FailedToSignIn(),
        );

        $authenticator = new LogInFirebase($auth);

        $this->expectException(InvalidTokenException::class);

        $authenticator->logInWithEmail('hugues.gobet@gmail.com', 'pedro');
    }

    public function testLogInWithEmailInvalidPayload(): void
    {
        $auth = $this->createMock(Auth::class);
        $auth->method('signInWithEmailAndPassword')->willReturn(
            SignInResult::fromData([]),
        );

        $authenticator = new LogInFirebase($auth);

        $this->expectException(InvalidPayloadException::class);

        $authenticator->logInWithEmail('hugues.gobet@gmail.com', 'password');
    }
}
