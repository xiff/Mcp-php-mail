<?php

declare(strict_types=1);

namespace MailMcp\Tests;

use MailMcp\Db;
use MailMcp\RateLimiter;
use PHPUnit\Framework\TestCase;

final class RateLimiterTest extends TestCase
{
    private int $now = 1_000_000;
    private RateLimiter $rl;

    protected function setUp(): void
    {
        $this->rl = new RateLimiter(Db::connect(sys_get_temp_dir() . '/mailmcp-rl-' . bin2hex(random_bytes(4)) . '.sqlite'), fn () => $this->now);
    }

    public function testExponentialBackoffThenLockoutAfterFiveFailures(): void
    {
        $this->assertNull($this->rl->loginBlockedFor('ip:a', 'global'));
        for ($i = 1; $i <= 4; $i++) {
            $this->assertSame([], $this->rl->loginFailed('ip:a', 'global'));
            $this->assertSame(2 ** $i, $this->rl->loginBlockedFor('ip:a', 'global'));
            $this->now += 2 ** $i;
            $this->assertNull($this->rl->loginBlockedFor('ip:a', 'global'));
        }
        $this->assertSame(['ip:a', 'global'], $this->rl->loginFailed('ip:a', 'global'));
        $this->now += 60;
        $this->assertSame(RateLimiter::LOCK_SECONDS - 60, $this->rl->loginBlockedFor('ip:a', 'global'));
        // Le verrou global bloque aussi une autre IP.
        $this->assertNotNull($this->rl->loginBlockedFor('ip:b', 'global'));
        $this->now += RateLimiter::LOCK_SECONDS;
        $this->assertNull($this->rl->loginBlockedFor('ip:a', 'global'));
        $this->rl->loginSucceeded('ip:a', 'global');
        $this->assertNull($this->rl->loginBlockedFor('ip:a', 'global'));
    }

    public function testFixedWindow(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($this->rl->hit('k', 3, 60));
        }
        $this->assertFalse($this->rl->hit('k', 3, 60));
        $this->now += 60;
        $this->assertTrue($this->rl->hit('k', 3, 60));
    }
}
