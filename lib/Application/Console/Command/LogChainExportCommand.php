<?php

/*  Poweradmin, a friendly web-based admin tool for PowerDNS.
 *  See <https://www.poweradmin.org> for more details.
 *
 *  Copyright 2007-2010 Rejo Zenger <rejo@zenger.nl>
 *  Copyright 2010-2026 Poweradmin Development Team
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


namespace Poweradmin\Application\Console\Command;

use InvalidArgumentException;
use Poweradmin\Application\Console\Arguments;
use Poweradmin\Application\Console\CommandInterface;
use Poweradmin\Domain\Port\ActorInterface;
use Poweradmin\Infrastructure\Logger\Integrity\IntegrityVerifier;

/**
 * log:chain-export - writes the integrity chain as chain.jsonl, and the newest stored
 * checkpoint as checkpoint, into a directory. The files hold hashes only, no log content;
 * they are what the anchoring job signs and what "dlog verify" checks offline.
 */
final class LogChainExportCommand implements CommandInterface
{
    public const NAME = 'log:chain-export';

    private IntegrityVerifier $verifier;

    public function __construct(IntegrityVerifier $verifier)
    {
        $this->verifier = $verifier;
    }

    public static function name(): string
    {
        return self::NAME;
    }

    public static function description(): string
    {
        return 'Write the integrity chain (chain.jsonl) and its newest checkpoint into the directory given';
    }

    public static function options(): array
    {
        return [];
    }

    public function run(Arguments $arguments, ActorInterface $actor, $stdout, $stderr): int
    {
        $positionals = $arguments->positionals();
        if (count($positionals) !== 1 || !is_dir($positionals[0])) {
            throw new InvalidArgumentException(self::NAME . ' takes one argument, an existing directory');
        }

        $lines = $this->verifier->lines();
        // Written as bytes with LF only: the hashes are over exactly these bytes
        file_put_contents($positionals[0] . '/chain.jsonl', $lines === [] ? '' : implode("\n", $lines) . "\n");
        $checkpoint = $this->verifier->storedCheckpoint();
        if ($checkpoint !== null) {
            file_put_contents($positionals[0] . '/checkpoint', $checkpoint);
        }
        fwrite($stdout, sprintf("%d lines%s\n", count($lines), $checkpoint === null ? ', no checkpoint yet' : ''));

        return 0;
    }
}
