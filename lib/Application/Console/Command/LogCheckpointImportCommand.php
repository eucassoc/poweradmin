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
use PDO;
use Poweradmin\Application\Console\Arguments;
use Poweradmin\Application\Console\CommandInterface;
use Poweradmin\Domain\Port\ActorInterface;

/**
 * log:checkpoint-import - stores a signed, cosigned checkpoint next to the chain, so that
 * log:verify and the web interface can show how far the chain is anchored. The checkpoint is
 * made outside the application (addons/integrity/anchor.sh); the copy stored here is a
 * convenience, the copies kept elsewhere are the reference.
 */
final class LogCheckpointImportCommand implements CommandInterface
{
    public const NAME = 'log:checkpoint-import';

    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public static function name(): string
    {
        return self::NAME;
    }

    public static function description(): string
    {
        return 'Store a signed and cosigned checkpoint of the integrity chain, read from the file given';
    }

    public static function options(): array
    {
        return [];
    }

    public function run(Arguments $arguments, ActorInterface $actor, $stdout, $stderr): int
    {
        $positionals = $arguments->positionals();
        $note = count($positionals) === 1 ? @file_get_contents($positionals[0]) : false;
        if ($note === false) {
            throw new InvalidArgumentException(self::NAME . ' takes one argument, a checkpoint file');
        }
        $body = explode("\n", explode("\n\n", $note, 2)[0]);
        if (count($body) !== 3 || preg_match('/^(0|[1-9][0-9]*)$/', $body[1]) !== 1) {
            throw new InvalidArgumentException('The file is not a signed checkpoint');
        }

        $stmt = $this->db->prepare('INSERT INTO log_integrity_checkpoints (size, note) VALUES (:size, :note)');
        $stmt->bindValue(':size', (int) $body[1], PDO::PARAM_INT);
        $stmt->bindValue(':note', $note, PDO::PARAM_STR);
        $stmt->execute();
        fwrite($stdout, sprintf("stored the checkpoint for %d lines\n", (int) $body[1]));

        return 0;
    }
}
