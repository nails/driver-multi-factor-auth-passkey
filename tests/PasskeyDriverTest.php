<?php

namespace Nails\MFA\Driver\Authentication\Tests;

use Nails\Auth\Resource\User;
use Nails\MFA\Driver\Authentication\Passkey;
use Nails\MFA\Exception\InvalidCodeException;
use Nails\MFA\Resource\Token;
use PHPUnit\Framework\TestCase;

final class PasskeyDriverTest extends TestCase
{
    public function testRequiresEnrollment(): void
    {
        self::assertTrue((new Passkey())->requiresEnrollment());
    }

    // --------------------------------------------------------------------------

    public function testHidesCodeInput(): void
    {
        self::assertTrue((new Passkey())->hidesCodeInput());
    }

    // --------------------------------------------------------------------------

    public function testCannotTryAgain(): void
    {
        //  A passkey ceremony is not a code that can be reissued like an email/SMS one
        self::assertFalse((new Passkey())->canTryAgain());
    }

    // --------------------------------------------------------------------------

    /**
     * A token whose `user` property is already populated: Token::user() then
     * returns it directly without touching the database, so validate() can be
     * exercised without booting Nails.
     */
    private function tokenFor(User $oUser, ?string $sChallenge = null): Token
    {
        return new Token([
            'user' => $oUser,
            'data' => $sChallenge !== null
                ? json_encode([Passkey::TOKEN_KEY_CHALLENGE => $sChallenge])
                : null,
        ]);
    }

    // --------------------------------------------------------------------------

    public function testValidateRejectsNonJsonCode(): void
    {
        $this->expectException(InvalidCodeException::class);

        (new Passkey())->validate(
            $this->tokenFor(new User(), 'some-challenge'),
            'this is not json'
        );
    }

    // --------------------------------------------------------------------------

    public function testValidateRejectsAScalarJsonCode(): void
    {
        //  Valid JSON, but not the credential object the client is supposed to send
        $this->expectException(InvalidCodeException::class);

        (new Passkey())->validate(
            $this->tokenFor(new User(), 'some-challenge'),
            '"just a string"'
        );
    }

    // --------------------------------------------------------------------------

    public function testValidateRejectsWhenNoChallengeIsOnTheToken(): void
    {
        $this->expectException(InvalidCodeException::class);

        (new Passkey())->validate(
            $this->tokenFor(new User(), null),
            json_encode(['id' => 'abc', 'response' => (object) []]) ?: '{}'
        );
    }

    // --------------------------------------------------------------------------

    public function testSetupCompleteInExistingModeDoesNotRequireTheCode(): void
    {
        $oResult = (new Passkey())->setupComplete(
            new User(),
            'irrelevant',
            (object) ['mode' => 'existing', 'count' => 2]
        );

        self::assertEquals((object) [], $oResult);
    }

    // --------------------------------------------------------------------------

    public function testGetSetupMarkupInExistingModeDoesNotRunAnyCeremony(): void
    {
        $sMarkup = (new Passkey())->getSetupMarkup(
            new User(),
            (object) ['mode' => 'existing', 'count' => 1]
        );

        self::assertStringNotContainsString('data-passkey-create', $sMarkup);
        //  No name="code" input of its own: the surrounding view already supplies
        //  the shared hidden #input-code, and a second one with the same name
        //  would collide with it.
        self::assertStringNotContainsString('name="code"', $sMarkup);
        self::assertStringContainsString('already have 1 passkey', $sMarkup);
        /**
         * The surrounding views hide their own generic Confirm/Verify button
         * whenever hidesCodeInput() is true, so this branch must supply its own
         * plain, always-visible submit trigger or there is nothing to click.
         */
        self::assertStringContainsString('type="submit"', $sMarkup);
        self::assertStringContainsString('name="action" value="setup_confirm"', $sMarkup);
    }

    // --------------------------------------------------------------------------

    public function testGetSetupMarkupInCreateModeRendersTheCeremonyButton(): void
    {
        $sMarkup = (new Passkey())->getSetupMarkup(
            new User(),
            (object) [
                'mode'    => 'create',
                'options' => (object) ['challenge' => 'abc123'],
            ]
        );

        self::assertStringContainsString('data-passkey-create', $sMarkup);
        self::assertStringContainsString('data-action="setup_confirm"', $sMarkup);
        self::assertStringContainsString('data-target="#input-code"', $sMarkup);
        self::assertStringContainsString('challenge', $sMarkup);
    }
}
