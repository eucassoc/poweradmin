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
use Poweradmin\Domain\Config\ConfigurationInterface;
use Poweradmin\Domain\Port\ActorInterface;
use Poweradmin\Infrastructure\Logger\Integrity\IntegrityVerifier;

/**
 * log:verify - checks the log tables against the integrity chain, and the chain against the
 * newest signed and cosigned checkpoint. Exits 0 when everything holds, 1 when something
 * does not, and says which row or line and why.
 */
final class LogVerifyCommand implements CommandInterface
{
    public const NAME = 'log:verify';

    private IntegrityVerifier $verifier;
    private ConfigurationInterface $config;

    public function __construct(IntegrityVerifier $verifier, ConfigurationInterface $config)
    {
        $this->verifier = $verifier;
        $this->config = $config;
    }

    public static function name(): string
    {
        return self::NAME;
    }

    public static function description(): string
    {
        return 'Check the log tables against the integrity chain and its cosigned checkpoint (logging.integrity_chain)';
    }

    public static function options(): array
    {
        return ['checkpoint', 'operator-key', 'witness-key', 'quorum', 'chain-only'];
    }

    public function run(Arguments $arguments, ActorInterface $actor, $stdout, $stderr): int
    {
        if ($arguments->positionals() !== []) {
            throw new InvalidArgumentException(self::NAME . ' takes no arguments');
        }

        $operatorKey = $this->keyOption($arguments, 'operator-key') ?? (string) $this->config->get('logging', 'integrity_chain_operator_key', '');
        $witnessKey = $this->keyOption($arguments, 'witness-key');
        $witnessKeys = $witnessKey !== null ? [$witnessKey] : array_values((array) $this->config->get('logging', 'integrity_chain_witness_keys', []));
        $quorum = $arguments->positiveInt('quorum') ?? count($witnessKeys);

        $checkpoint = null;
        if (!$arguments->has('chain-only')) {
            // A copy kept outside the database is the stronger reference: the stored one can be deleted with the rows
            $checkpoint = $arguments->has('checkpoint')
                ? $this->read((string) $arguments->value('checkpoint'))
                : $this->verifier->storedCheckpoint();
        }

        $result = $this->verifier->verify($checkpoint, $operatorKey, $witnessKeys, $quorum, !$arguments->has('chain-only') && $operatorKey !== '');

        foreach ($result['notes'] as $note) {
            fwrite($stdout, 'ok    ' . $note . "\n");
        }
        foreach ($result['failures'] as $failure) {
            fwrite($stdout, 'FAIL  ' . $failure . "\n");
        }
        fwrite($stdout, sprintf(
            "%s: %d lines, head %s\n",
            $result['ok'] ? 'verified' : 'NOT VERIFIED',
            $result['lines'],
            $result['head'] ?? '-'
        ));

        return $result['ok'] ? 0 : 1;
    }

    private function keyOption(Arguments $arguments, string $name): ?string
    {
        return $arguments->has($name) ? trim($this->read((string) $arguments->value($name))) : null;
    }

    private function read(string $file): string
    {
        $content = $file === '' ? false : @file_get_contents($file);
        if ($content === false) {
            throw new InvalidArgumentException(sprintf('Cannot read "%s"', $file));
        }

        return $content;
    }
}
