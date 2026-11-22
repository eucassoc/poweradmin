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
use Poweradmin\Infrastructure\Logger\Integrity\IntegrityChain;
use Poweradmin\Infrastructure\Logger\Integrity\LogMaintenance;

/**
 * log:prune - deletes log rows older than --keep-days (or written before --before) and, with logging.integrity_chain on,
 * appends a line to the chain saying so. A stand-in for the retention CLI of issue 1172.
 */
final class LogPruneCommand implements CommandInterface
{
    public const NAME = 'log:prune';

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
        return 'Delete rows of a log table older than --keep-days and record the pruning in the integrity chain';
    }

    public static function options(): array
    {
        return ['table', 'keep-days', 'before'];
    }

    public function run(Arguments $arguments, ActorInterface $actor, $stdout, $stderr): int
    {
        $table = (string) $arguments->value('table');
        $days = $arguments->positiveInt('keep-days');
        $before = $arguments->value('before');
        if (!isset(IntegrityChain::TABLES[$table]) || ($days === null) === ($before === null)) {
            throw new InvalidArgumentException(
                self::NAME . ' needs --table=<' . implode('|', array_keys(IntegrityChain::TABLES)) . '> and one of --keep-days=<n>, --before="<Y-m-d H:i:s, UTC>"'
            );
        }
        if ($before !== null && preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $before) !== 1) {
            throw new InvalidArgumentException('Option --before expects a UTC time such as "2026-01-31 00:00:00"');
        }

        $count = $before !== null
            ? $this->maintenance->prune($table, $before, 'retention: rows written before ' . $before . ' UTC')
            : $this->maintenance->prune($table, gmdate('Y-m-d H:i:s', time() - $days * 86400), sprintf('retention: %d days', $days));
        fwrite($stdout, sprintf("%d rows pruned from %s\n", $count, $table));

        return 0;
    }
}
