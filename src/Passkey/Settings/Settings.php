<?php

namespace Nails\MFA\Driver\Authentication\Passkey\Settings;

use Nails\Common\Interfaces;
use Nails\Components\Setting;
use Nails\Factory;

class Settings implements Interfaces\Component\Settings
{
    const KEY_LABEL                = 'label';
    const KEY_FEEDBACK_PROMPT      = 'feedback_prompt';
    const KEY_FEEDBACK_INVALID     = 'feedback_invalid';
    const KEY_DEFAULT_PASSKEY_LABEL = 'default_passkey_label';

    // --------------------------------------------------------------------------

    public function getLabel(): string
    {
        return 'MFA: Passkey';
    }

    // --------------------------------------------------------------------------

    public function getPermissions(): array
    {
        return [];
    }

    // --------------------------------------------------------------------------

    public function get(): array
    {
        /** @var Setting $oLabel */
        $oLabel = Factory::factory('ComponentSetting');
        $oLabel
            ->setKey(static::KEY_LABEL)
            ->setLabel('Label')
            ->setDefault('Passkey')
            ->setInfo('Shown to the user as the name of this verification method.');

        /** @var Setting $oPrompt */
        $oPrompt = Factory::factory('ComponentSetting');
        $oPrompt
            ->setKey(static::KEY_FEEDBACK_PROMPT)
            ->setLabel('Prompt')
            ->setFieldset('User Feedback')
            ->setDefault('Use your passkey to verify it’s you.');

        /** @var Setting $oInvalid */
        $oInvalid = Factory::factory('ComponentSetting');
        $oInvalid
            ->setKey(static::KEY_FEEDBACK_INVALID)
            ->setLabel('Invalid Passkey')
            ->setFieldset('User Feedback')
            ->setDefault('That passkey could not be verified. Please try again.');

        /** @var Setting $oDefaultLabel */
        $oDefaultLabel = Factory::factory('ComponentSetting');
        $oDefaultLabel
            ->setKey(static::KEY_DEFAULT_PASSKEY_LABEL)
            ->setLabel('Default passkey label')
            ->setFieldset('User Feedback')
            ->setDefault('Passkey')
            ->setInfo('Used to name a newly registered passkey when the authenticator is not recognised.');

        return [
            $oLabel,
            $oPrompt,
            $oInvalid,
            $oDefaultLabel,
        ];
    }
}
