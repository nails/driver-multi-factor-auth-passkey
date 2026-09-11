<?php

namespace Nails\MFA\Driver\Authentication\Tests;

use Nails\Auth\Events;
use Nails\Common\Interfaces\Event\Subscription;
use Nails\MFA\Driver\Authentication\Passkey\Event\Listener\User\RemovePasskey;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

/**
 * RemovePasskey's constructor calls Events::getEventNamespace(), which walks the
 * booted app's component registry (Components::available(), keyed off
 * NAILS_APP_PATH) — every other Subscription listener in the MFA ecosystem has the
 * same shape and, for the same reason, none of them are instantiated in a bare unit
 * test. This checks what is checkable without an app: the class is wired up right.
 */
final class RemovePasskeyListenerTest extends TestCase
{
    public function testItImplementsSubscription(): void
    {
        self::assertTrue((new ReflectionClass(RemovePasskey::class))->implementsInterface(Subscription::class));
    }

    // --------------------------------------------------------------------------

    public function testItSubscribesToPasskeyRemoval(): void
    {
        $oConstructor = (new ReflectionClass(RemovePasskey::class))->getConstructor();
        self::assertNotNull($oConstructor);

        //  setEvent()/setNamespace()/setCallback() are the only calls the
        //  constructor makes; asserting the source calls setEvent() with the right
        //  constant is as far as this can go without an app to resolve
        //  getEventNamespace() against.
        $sSource = file_get_contents((string) $oConstructor->getFileName());
        self::assertIsString($sSource);
        self::assertStringContainsString('Events::USER_DID_REMOVE_PASSKEY', $sSource);
        self::assertSame('AUTH:USER:PASSKEY:REMOVED', Events::USER_DID_REMOVE_PASSKEY);
    }

    // --------------------------------------------------------------------------

    public function testExecuteAcceptsAUserId(): void
    {
        $oExecute = new ReflectionMethod(RemovePasskey::class, 'execute');

        self::assertSame('void', (string) $oExecute->getReturnType());
        self::assertCount(1, $oExecute->getParameters());
        self::assertSame('int', (string) $oExecute->getParameters()[0]->getType());
    }
}
