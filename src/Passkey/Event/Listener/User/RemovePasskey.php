<?php

namespace Nails\MFA\Driver\Authentication\Passkey\Event\Listener\User;

use Nails\Auth;
use Nails\Auth\Events;
use Nails\Common\Events\Subscription;
use Nails\Factory;
use Nails\MFA;
use Nails\MFA\Driver\Authentication\Passkey\Constants;
use Nails\MFA\Service\Logger;
use Nails\MFA\Service\MultiFactorAuth;
use Throwable;

/**
 * Keeps the "Passkey" MFA method honest when a user's last passkey is revoked.
 *
 * One passkey enrolment serves both passwordless sign-in and MFA, so the module
 * deliberately never deletes a passkey when the MFA method is removed (see
 * Passkey::reset()). The reverse direction still needs handling though: without
 * this, revoking someone's only passkey — from `/auth/passkeys`, or an admin doing
 * it from the user's account — leaves them enrolled in an MFA method they can never
 * again satisfy, and (on a REQUIRED policy) with no other way to sign in.
 *
 * This lives in the driver, not module-multi-factor-auth, because it is the only
 * package that legitimately knows about both module-auth's passkeys and the MFA
 * module's methods; the core module stays driver-agnostic.
 */
class RemovePasskey extends Subscription
{
    public function __construct()
    {
        $this
            ->setEvent(Events::USER_DID_REMOVE_PASSKEY)
            ->setNamespace(Events::getEventNamespace())
            ->setCallback([$this, 'execute']);
    }

    // --------------------------------------------------------------------------

    public function execute(int $iUserId): void
    {
        /** @var Logger $oLogger */
        $oLogger = Factory::service('Logger', MFA\Constants::MODULE_SLUG);

        /** @var Auth\Model\User $oUserModel */
        $oUserModel = Factory::model('User', Auth\Constants::MODULE_SLUG);
        /** @var Auth\Resource\User|null $oUser */
        $oUser = $oUserModel->getById($iUserId);

        if ($oUser === null) {
            return;
        }

        /** @var Auth\Model\User\Passkey $oPasskeyModel */
        $oPasskeyModel = Factory::model('UserPasskey', Auth\Constants::MODULE_SLUG);

        if ($oPasskeyModel->countForUser($iUserId) > 0) {
            //  They still have other passkeys; the MFA method is still usable.
            return;
        }

        /** @var MultiFactorAuth $oMfaService */
        $oMfaService = Factory::service('MultiFactorAuth', MFA\Constants::MODULE_SLUG);

        if (!$oMfaService->getUserMethod($oUser, Constants::MODULE_SLUG)) {
            //  Not enrolled in passkey MFA; nothing to clean up.
            return;
        }

        try {

            /**
             * bAllowLastRequired: true — if this was their last verification method
             * on a REQUIRED policy, leaving it in place would be worse than removing
             * it. With it gone they are routed through forced setup of a new method
             * on next sign-in, rather than being stuck on a challenge they can never
             * complete.
             */
            $oMfaService->removeMethod($oUser, Constants::MODULE_SLUG, true);

            $oLogger->info(sprintf(
                'Removed passkey MFA method for user %s: their last passkey was revoked',
                $iUserId
            ));

        } catch (Throwable $e) {
            $oLogger->error(sprintf(
                'Could not remove passkey MFA method for user %s after their last passkey was revoked: [%s] %s',
                $iUserId,
                $e::class,
                $e->getMessage()
            ));
        }
    }
}
