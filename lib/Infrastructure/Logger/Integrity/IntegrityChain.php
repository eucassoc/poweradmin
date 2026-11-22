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

namespace Poweradmin\Infrastructure\Logger\Integrity;

use PDO;
use PDOException;
use Poweradmin\Domain\Config\ConfigurationInterface;
use Poweradmin\Infrastructure\Configuration\ConfigurationManager;
use RuntimeException;

/**
 * The optional tamper-evident chain over the log tables (logging.integrity_chain).
 *
 * Every row written to a log table gets one line in log_integrity_chain. A line is a
 * deedlog evidence-chain record (https://github.com/eucassoc/deedlog, spec/evidence-chain.md):
 * it holds the keyed digest (HMAC-SHA-256) of the row and the SHA-256 of the line before it.
 * The line never holds the row's content, so a row can later be anonymised or pruned without
 * touching the chain; that operation is appended as a line of its own.
 *
 * Lines are hashed as bytes. A line is built once and stored as text, never re-encoded.
 *
 * This class only appends. Signing a checkpoint and having it cosigned happens outside the
 * application, with a key the application and its database account never see
 * (addons/integrity/anchor.sh).
 */
final class IntegrityChain
{
    public const SPEC = 'deedlog/v0.1';
    public const COLLECTOR = 'poweradmin-integrity/0.1';

    public const EVENT_OPENED = 'chain.opened';
    public const EVENT_ROW_WRITTEN = 'row.written';
    public const EVENT_ROW_ANONYMIZED = 'row.anonymized';
    public const EVENT_ROWS_PRUNED = 'rows.pruned';

    /**
     * The log tables and the columns that make up a row's digest, in this order.
     */
    public const TABLES = [
        'log_users' => ['id', 'event', 'priority', 'created_at'],
        'log_zones' => ['id', 'zone_id', 'event', 'priority', 'created_at'],
        'log_groups' => ['id', 'group_id', 'event', 'priority', 'created_at'],
        'log_api' => ['id', 'event', 'priority', 'created_at'],
        'log_changesets' => ['id', 'zone_id', 'user_id', 'username', 'comment', 'client_ip', 'created_at'],
        'log_record_changes' => [
            'id', 'zone_id', 'changeset_id', 'record_id', 'action', 'user_id', 'username',
            'before_state', 'after_state', 'client_ip', 'created_at',
        ],
    ];

    /** The sequences behind the id columns on PostgreSQL, as sql/poweradmin-pgsql-db-structure.sql names them */
    private const SEQUENCES = [
        'log_users' => 'log_users_id_seq1',
        'log_zones' => 'log_zones_id_seq1',
        'log_groups' => 'log_groups_id_seq1',
        'log_api' => 'log_api_id_seq1',
        'log_changesets' => 'log_changesets_id_seq',
        'log_record_changes' => 'log_record_changes_id_seq1',
    ];

    /** What the chain records; its SHA-256 is the subject of the first line */
    public const DECLARATION = 'Every row written to the Poweradmin log tables after this line: one row.written line per row, '
        . 'whose subject is the HMAC-SHA-256 of the JSON object of the row\'s columns (names and order as in '
        . 'IntegrityChain::TABLES, every value a string or null, no whitespace, UTF-8). Rows with an id up to '
        . 'baseline.<table> were written before the chain was opened and are not covered. A row.anonymized line '
        . 'replaces the digest of one row; a rows.pruned line states that every row of a table with an id up to '
        . 'through_id was deleted.';

    private const MAX_APPEND_ATTEMPTS = 5;

    private PDO $db;
    private bool $enabled;
    private string $origin;
    private string $key;

    /** @var array{0: string, 1: int}|null The row being appended, so that opening the chain does not count it as old */
    private ?array $current = null;

    public function __construct(PDO $db, ConfigurationInterface $config)
    {
        $this->db = $db;
        $this->enabled = (bool) $config->get('logging', 'integrity_chain', false);
        $this->origin = (string) $config->get('logging', 'integrity_chain_origin', '');
        $this->key = self::loadKey($config);
    }

    /**
     * Called by the log writers right after their INSERT. With the setting off this is one
     * configuration lookup and nothing else.
     */
    public static function afterInsert(PDO $db, string $table): void
    {
        $config = ConfigurationManager::getInstance();
        $config->initialize();
        if (!$config->get('logging', 'integrity_chain', false)) {
            return;
        }

        $id = (int) $db->lastInsertId(self::SEQUENCES[$table] ?? null);
        if ($id > 0) {
            (new self($db, $config))->rowWritten($table, $id);
        }
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function origin(): string
    {
        return $this->origin;
    }

    /** A short public name for the HMAC key in use, so a verifier knows which key a line needs */
    public function keyId(): string
    {
        return substr(hash('sha256', "poweradmin-integrity-key-id\n" . $this->key), 0, 8);
    }

    public function rowWritten(string $table, int $id): void
    {
        $this->appendRow(self::EVENT_ROW_WRITTEN, $table, $id, []);
    }

    /** Records that one row was rewritten on purpose (for example a deleted user's name) */
    public function rowAnonymized(string $table, int $id, string $reason): void
    {
        $this->appendRow(self::EVENT_ROW_ANONYMIZED, $table, $id, ['reason' => $reason]);
    }

    /** Records that every row of $table with an id up to $throughId was deleted on purpose */
    public function rowsPruned(string $table, int $throughId, int $count, string $reason): void
    {
        self::assertTable($table);
        $statement = self::json(['table' => $table, 'through_id' => (string) $throughId, 'count' => (string) $count, 'reason' => $reason]);
        $this->append(
            ['media_type' => 'application/json', 'size' => strlen($statement), 'digest' => ['sha256' => hash('sha256', $statement)]],
            ['event' => self::EVENT_ROWS_PRUNED, 'table' => $table, 'through_id' => (string) $throughId, 'count' => (string) $count, 'reason' => $reason]
        );
    }

    /**
     * The digest input for one row: its columns as a JSON object, values as strings or null.
     *
     * @return string|null null when the row does not exist
     */
    public static function rowBody(PDO $db, string $table, int $id): ?string
    {
        self::assertTable($table);
        $stmt = $db->prepare('SELECT ' . implode(', ', self::TABLES[$table]) . ' FROM ' . $table . ' WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : self::bodyOf($table, $row);
    }

    /** @param array<string, mixed> $row */
    public static function bodyOf(string $table, array $row): string
    {
        $body = [];
        foreach (self::TABLES[$table] as $column) {
            $value = $row[$column] ?? null;
            $body[$column] = $value === null ? null : (string) $value;
        }

        return self::json($body);
    }

    public function digest(string $body): string
    {
        return hash_hmac('sha256', $body, $this->key);
    }

    /** @param array<string, string> $extraMeta */
    private function appendRow(string $event, string $table, int $id, array $extraMeta): void
    {
        $body = self::rowBody($this->db, $table, $id);
        if ($body === null) {
            return;
        }

        $this->current = [$table, $id];
        $this->append(
            ['media_type' => 'application/json', 'size' => strlen($body), 'digest' => ['hmac-sha256' => $this->digest($body)]],
            ['event' => $event, 'table' => $table, 'id' => (string) $id, 'key' => $this->keyId()] + $extraMeta
        );
    }

    /**
     * Appends one line. The sequence number is the primary key, so two requests that read the
     * same last line cannot both insert: the loser reads again and retries.
     *
     * @param array<string, mixed> $subject
     * @param array<string, string> $meta
     */
    private function append(array $subject, array $meta): void
    {
        $this->assertUsable();

        for ($attempt = 1; ; $attempt++) {
            $last = $this->db->query('SELECT seq, line FROM log_integrity_chain ORDER BY seq DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
            if ($last === false) {
                $this->open();
                continue;
            }

            $line = $this->line((int) $last['seq'] + 1, (string) $last['line'], $subject, $meta);
            if ($this->insert((int) $last['seq'] + 1, $line)) {
                return;
            }
            if ($attempt >= self::MAX_APPEND_ATTEMPTS) {
                throw new RuntimeException('The integrity chain could not be extended; another writer kept winning');
            }
        }
    }

    /** Writes line 0: what the chain records, and which rows were there before it */
    private function open(): void
    {
        $meta = ['event' => self::EVENT_OPENED, 'key' => $this->keyId()];
        foreach (array_keys(self::TABLES) as $table) {
            $max = (int) $this->db->query('SELECT COALESCE(MAX(id), 0) FROM ' . $table)->fetchColumn();
            // The row being logged right now is already in its table; it belongs to the chain, not to the baseline
            if ($this->current !== null && $this->current[0] === $table) {
                $max = min($max, $this->current[1] - 1);
            }
            $meta['baseline.' . $table] = (string) $max;
        }
        $subject = ['media_type' => 'text/plain', 'size' => strlen(self::DECLARATION), 'digest' => ['sha256' => hash('sha256', self::DECLARATION)]];
        $this->insert(0, $this->line(0, null, $subject, $meta));
    }

    /**
     * @param array<string, mixed> $subject
     * @param array<string, string> $meta
     */
    private function line(int $seq, ?string $previousLine, array $subject, array $meta): string
    {
        $record = ['spec' => self::SPEC, 'chain' => $this->origin, 'seq' => $seq];
        if ($previousLine !== null) {
            $record['prev'] = 'sha256:' . hash('sha256', $previousLine);
        }
        $record['collected_at'] = gmdate('Y-m-d\TH:i:s\Z');
        $record['source'] = ['type' => 'audit-log', 'id' => 'poweradmin', 'collector' => self::COLLECTOR];
        $record['subject'] = $subject;
        $record['meta'] = $meta;

        return self::json($record);
    }

    private function insert(int $seq, string $line): bool
    {
        try {
            $stmt = $this->db->prepare('INSERT INTO log_integrity_chain (seq, line) VALUES (:seq, :line)');
            $stmt->bindValue(':seq', $seq, PDO::PARAM_INT);
            $stmt->bindValue(':line', $line, PDO::PARAM_STR);
            $stmt->execute();

            return true;
        } catch (PDOException $e) {
            // SQLSTATE class 23 is an integrity constraint violation: the sequence number is taken
            if (str_starts_with((string) $e->getCode(), '23')) {
                return false;
            }
            throw $e;
        }
    }

    private function assertUsable(): void
    {
        if ($this->origin === '' || preg_match('/[\s+\x00-\x1f]/', $this->origin) === 1 || strlen($this->origin) > 255) {
            throw new RuntimeException('logging.integrity_chain is on but logging.integrity_chain_origin is not a valid name (no spaces, no "+")');
        }
        if (strlen($this->key) < 32) {
            throw new RuntimeException('logging.integrity_chain is on but logging.integrity_chain_key_file does not hold a key of at least 32 bytes');
        }
    }

    private static function assertTable(string $table): void
    {
        if (!isset(self::TABLES[$table])) {
            throw new RuntimeException(sprintf('"%s" is not a log table', $table));
        }
    }

    /** The HMAC key: a file outside the database (preferred) or, for tests, the setting itself */
    private static function loadKey(ConfigurationInterface $config): string
    {
        $file = (string) $config->get('logging', 'integrity_chain_key_file', '');
        if ($file !== '' && is_readable($file)) {
            return trim((string) file_get_contents($file));
        }

        return (string) $config->get('logging', 'integrity_chain_key', '');
    }

    /** @param array<string, mixed> $value */
    private static function json(array $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
