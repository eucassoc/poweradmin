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
use Poweradmin\Infrastructure\Logger\Integrity\LogMaintenance;

/**
 * log:anonymize-user - replaces a user's name and client address in the log rows and, with
 * logging.integrity_chain on, appends one line per rewritten row to the chain. A stand-in
 * for the anonymisation of issue 1861.
 */
final class LogAnonymizeUserCommand implements CommandInterface
{
    public const NAME = 'log:anonymize-user';

    private LogMaintenance $maintenance;

    public function __construct(LogMaintenance $maintenance)
    {
        $this->maintenance = $maintenance;
    }

    public static function name(): string
    {
        return self::NAME;
    }

    public static function description(): string
    {
        return 'Replace a user name in the log rows by --replacement and record each rewrite in the integrity chain';
    }

    public static function options(): array
    {
        return ['replacement'];
    }

    public function run(Arguments $arguments, ActorInterface $actor, $stdout, $stderr): int
    {
        $positionals = $arguments->positionals();
        $replacement = (string) $arguments->value('replacement');
        if (count($positionals) !== 1 || preg_match('/^[A-Za-z0-9._-]+$/', $replacement) !== 1) {
            throw new InvalidArgumentException(self::NAME . ' takes a user name and --replacement=<name>, such as deleted-user-7');
        }

        fwrite($stdout, sprintf("%d log rows rewritten\n", $this->maintenance->anonymizeUser($positionals[0], $replacement)));

        return 0;
    }
}
