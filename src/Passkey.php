<?php

namespace Nails\MFA\Driver\Authentication;

use Nails\Auth;
use Nails\Auth\Resource\User;
use Nails\Common\Driver\Base;
use Nails\Common\Service\Asset;
use Nails\Common\Service\UserFeedback;
use Nails\Factory;
use Nails\MFA\Driver\Authentication\Passkey\Settings\Settings;
use Nails\MFA\Exception\InvalidCodeException;
use Nails\MFA\Exception\MfaException;
use Nails\MFA\Interfaces\Authentication\Driver;
use Nails\MFA\Interfaces\Authentication\Driver\Interactive;
use Nails\MFA\Resource\Token;
use Nails\MFA\Resource\UserMethod;
use stdClass;

/**
 * The "Passkey" MFA driver.
 *
 * Unlike Email/Authenticator this is not a code the user types: the challenge and
 * setup screens run a WebAuthn ceremony in the browser (see the Interactive
 * interface) and hand the result back as JSON in the shared, hidden `code` input.
 * All of the WebAuthn/library detail lives in module-auth's Passkey service; this
 * class only adapts it to the MFA module's driver contract.
 */
class Passkey extends Base implements Driver, Interactive
{
    /**
     * Where the challenge minted for the current verify attempt is stashed on the
     * token. A nonce, so it is fine unencrypted in `mfa_token.data` alongside the
     * driver/setup bookkeeping the module already stores there.
     */
    const TOKEN_KEY_CHALLENGE = 'passkey_challenge';

    // --------------------------------------------------------------------------

    public function getLabel(): string
    {
        $sLabel = $this->getSetting(Settings::KEY_LABEL);

        return is_string($sLabel) && $sLabel !== ''
            ? $sLabel
            : 'Passkey';
    }

    // --------------------------------------------------------------------------

    public function getDescription(): string
    {
        return 'Allows a user to verify with a passkey — a fingerprint, face, screen-lock PIN, or security key.';
    }

    // --------------------------------------------------------------------------

    public function getSetupDescription(): string
    {
        return 'Use a passkey — your fingerprint, face, screen-lock PIN, or a security key — to verify when you sign in.';
    }

    // --------------------------------------------------------------------------

    public function preForm(Token $oToken, UserFeedback $oUserFeedback): void
    {
        $oUserFeedback->success($this->getFeedbackPrompt());
    }

    // --------------------------------------------------------------------------

    public function postForm(Token $oToken): void
    {
        //  Not required
    }

    // --------------------------------------------------------------------------

    /**
     * @throws MfaException
     */
    public function getChallengeMarkup(Token $oToken): string
    {
        $oUser = $this->requireUser($oToken);

        /**
         * Minted here, not preForm(): a failed attempt re-renders this same view, and
         * doing it here keeps every render consistent with the challenge actually
         * stored on the token, rather than the one from the very first render.
         */
        $oOptions = $this->createAuthenticationOptions($oUser);

        $oToken->setData((object) [
            static::TOKEN_KEY_CHALLENGE => $oOptions->challenge,
        ]);

        return $this->ceremonyButton(
            'data-passkey-assert',
            $oOptions->options,
            'verify',
            'Use your passkey'
        );
    }

    // --------------------------------------------------------------------------

    /**
     * @throws MfaException
     */
    public function validate(Token $oToken, string $sCode): void
    {
        $oUser   = $this->requireUser($oToken);
        $aClient = $this->decodeClientResponse($sCode);

        $sChallenge = $oToken->getData(static::TOKEN_KEY_CHALLENGE);
        if (!is_string($sChallenge) || $sChallenge === '') {
            throw new InvalidCodeException($this->getFeedbackInvalid());
        }

        /** @var Auth\Service\Passkey $oPasskeys */
        $oPasskeys = Factory::service('Passkey', Auth\Constants::MODULE_SLUG);

        try {
            //  requireUserVerification: false — the password already served as the
            //  first factor, so this only needs to prove possession of the passkey.
            $oPasskeys->completeAuthentication($aClient, $sChallenge, $oUser, false);
        } catch (Auth\Exception\Passkey\PasskeyException) {
            throw new InvalidCodeException($this->getFeedbackInvalid());
        }

        $oToken->setData((object) [
            static::TOKEN_KEY_CHALLENGE => null,
        ]);
    }

    // --------------------------------------------------------------------------

    public function canTryAgain(): bool
    {
        return false;
    }

    // --------------------------------------------------------------------------

    public function resend(Token $oToken, UserFeedback $oUserFeedback): void
    {
        //  A passkey ceremony is not a code that can be reissued
    }

    // --------------------------------------------------------------------------

    public function requiresEnrollment(): bool
    {
        return true;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws MfaException
     */
    public function setupStart(User $oUser): stdClass
    {
        /** @var Auth\Service\Passkey $oPasskeys */
        $oPasskeys = Factory::service('Passkey', Auth\Constants::MODULE_SLUG);

        if (!$oPasskeys->isEnabled()) {
            throw new MfaException('Passkeys are not enabled for this application.');
        }

        $iCount = $this->countForUser($oUser);
        if ($iCount > 0) {
            /**
             * One enrolment serves both passwordless sign-in and MFA, so a user who
             * already has a passkey has nothing left to create — enrolling here just
             * confirms they want it used as their second factor too.
             */
            return (object) [
                'mode'  => 'existing',
                'count' => $iCount,
            ];
        }

        try {
            $oOptions = $oPasskeys->createRegistrationOptions($oUser);
        } catch (Auth\Exception\Passkey\PasskeyException $e) {
            throw new MfaException($e->getMessage(), $e->getCode(), $e);
        }

        return (object) [
            'mode'      => 'create',
            'challenge' => $oOptions->challenge,
            'options'   => $oOptions->options,
        ];
    }

    // --------------------------------------------------------------------------

    public function getSetupMarkup(User $oUser, stdClass $oPending): string
    {
        if (($oPending->mode ?? null) === 'existing') {

            $iCount = (int) ($oPending->count ?? 0);

            /**
             * No WebAuthn ceremony is needed here, so this is a plain, always-visible
             * submit button rather than a JS-driven one: the MFA views hide their own
             * generic Confirm/Verify button whenever hidesCodeInput() is true, on the
             * assumption the driver's own markup supplies a trigger, so this branch
             * must supply one itself or there is nothing left to click.
             *
             * No `code` input either: the views already render a shared hidden
             * #input-code field whenever hidesCodeInput() is true, so a second one
             * with the same `name` would collide with it, and setupComplete() below
             * never reads $sCode in this branch anyway.
             */
            return sprintf(
                '<p>%s</p><button type="submit" name="action" value="setup_confirm" class="btn btn--block btn--primary">%s</button>',
                htmlspecialchars(sprintf(
                    'You already have %d passkey%s registered. Continue to configure %s for two-factor '
                    . 'authentication.',
                    $iCount,
                    $iCount === 1 ? '' : 's',
                    $iCount === 1 ? 'it' : 'them'
                ), ENT_QUOTES),
                htmlspecialchars('Confirm', ENT_QUOTES)
            );
        }

        return $this->ceremonyButton(
            'data-passkey-create',
            $oPending->options ?? (object) [],
            'setup_confirm',
            'Create a passkey'
        );
    }

    // --------------------------------------------------------------------------

    /**
     * @throws InvalidCodeException
     */
    public function setupComplete(User $oUser, string $sCode, stdClass $oPending): stdClass
    {
        if (($oPending->mode ?? null) === 'existing') {
            return (object) [];
        }

        $aClient    = $this->decodeClientResponse($sCode);
        $sChallenge = is_string($oPending->challenge ?? null) ? $oPending->challenge : '';

        if ($sChallenge === '') {
            throw new InvalidCodeException($this->getFeedbackInvalid());
        }

        /** @var Auth\Service\Passkey $oPasskeys */
        $oPasskeys = Factory::service('Passkey', Auth\Constants::MODULE_SLUG);

        try {
            $oPasskey = $oPasskeys->completeRegistration(
                $oUser,
                $aClient,
                $sChallenge,
                $this->getDefaultPasskeyLabel()
            );
        } catch (Auth\Exception\Passkey\PasskeyException) {
            throw new InvalidCodeException($this->getFeedbackInvalid());
        }

        return (object) [
            'passkey_id' => $oPasskey->id,
        ];
    }

    // --------------------------------------------------------------------------

    public function reset(User $oUser, UserMethod $oMethod): void
    {
        /**
         * Un-enrolling this MFA method must never delete the user's passkeys: they
         * may still sign in with them directly (a user-verified passkey login skips
         * MFA entirely), and re-enrolling later should not force a new registration.
         */
    }

    // --------------------------------------------------------------------------

    /**
     * @throws \Nails\Common\Exception\FactoryException
     * @throws \Nails\Common\Exception\AssetException
     */
    public function loadAssets(): void
    {
        /** @var Asset $oAsset */
        $oAsset = Factory::service('Asset');
        $oAsset->load('passkey.min.js', Auth\Constants::MODULE_SLUG, 'JS', false, true);
    }

    // --------------------------------------------------------------------------

    public function hidesCodeInput(): bool
    {
        return true;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws MfaException
     */
    protected function requireUser(Token $oToken): User
    {
        $oUser = $oToken->user();
        if ($oUser === null) {
            throw new MfaException('Token is not associated with a user.');
        }

        return $oUser;
    }

    // --------------------------------------------------------------------------

    /**
     * @throws MfaException
     */
    protected function createAuthenticationOptions(User $oUser): stdClass
    {
        /** @var Auth\Service\Passkey $oPasskeys */
        $oPasskeys = Factory::service('Passkey', Auth\Constants::MODULE_SLUG);

        try {
            return $oPasskeys->createAuthenticationOptions($oUser, Auth\Service\Passkey::UV_PREFERRED);
        } catch (Auth\Exception\Passkey\PasskeyException $e) {
            throw new MfaException($e->getMessage(), $e->getCode(), $e);
        }
    }

    // --------------------------------------------------------------------------

    /**
     * @throws \Nails\Common\Exception\FactoryException
     * @throws \Nails\Common\Exception\ModelException
     */
    protected function countForUser(User $oUser): int
    {
        /** @var Auth\Model\User\Passkey $oModel */
        $oModel = Factory::model('UserPasskey', Auth\Constants::MODULE_SLUG);

        return $oModel->countForUser((int) $oUser->id);
    }

    // --------------------------------------------------------------------------

    /**
     * Renders the button the shared passkey.js binds to (see
     * bindDriverControls() in module-auth's assets/js/passkey.js): it reads the
     * ceremony options from `data-options`, runs create()/get(), writes the JSON
     * result into `data-target`, sets the form's `[name="action"]` field to
     * `data-action`, then submits. The hidden `[name="action"]` input it needs is
     * rendered by the MFA views alongside this markup, not here — this driver has
     * no view of its own beyond this fragment.
     */
    protected function ceremonyButton(string $sTrigger, stdClass $oOptions, string $sAction, string $sLabel): string
    {
        return sprintf(
            '<button type="button" %s data-options=\'%s\' data-target="#input-code" data-action="%s" class="btn btn--block btn--primary" hidden>%s</button>'
            . '<p class="form__feedback form__feedback--invalid" data-passkey-error hidden></p>',
            $sTrigger,
            htmlspecialchars(json_encode($oOptions) ?: '{}', ENT_QUOTES),
            htmlspecialchars($sAction, ENT_QUOTES),
            htmlspecialchars($sLabel, ENT_QUOTES)
        );
    }

    // --------------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     * @throws InvalidCodeException
     */
    protected function decodeClientResponse(string $sCode): array
    {
        $mDecoded = json_decode($sCode, true);
        if (!is_array($mDecoded)) {
            throw new InvalidCodeException($this->getFeedbackInvalid());
        }

        return $mDecoded;
    }

    // --------------------------------------------------------------------------

    protected function getFeedbackPrompt(): string
    {
        $sPrompt = $this->getSetting(Settings::KEY_FEEDBACK_PROMPT);

        return is_string($sPrompt) && $sPrompt !== ''
            ? $sPrompt
            : 'Use your passkey to verify it’s you.';
    }

    // --------------------------------------------------------------------------

    protected function getFeedbackInvalid(): string
    {
        $sInvalid = $this->getSetting(Settings::KEY_FEEDBACK_INVALID);

        return is_string($sInvalid) && $sInvalid !== ''
            ? $sInvalid
            : 'That passkey could not be verified. Please try again.';
    }

    // --------------------------------------------------------------------------

    protected function getDefaultPasskeyLabel(): ?string
    {
        $sLabel = $this->getSetting(Settings::KEY_DEFAULT_PASSKEY_LABEL);

        return is_string($sLabel) && $sLabel !== ''
            ? $sLabel
            : null;
    }
}
