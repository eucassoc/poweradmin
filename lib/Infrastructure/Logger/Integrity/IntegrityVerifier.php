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

/**
 * Checks the log tables against the integrity chain, and the chain against a signed,
 * cosigned checkpoint. Three questions, each answered separately in the result:
 *
 *  1. chain:      is every line linked to the one before it (deedlog evidence-chain §8)?
 *  2. rows:       does every log row still have the digest its line recorded?
 *  3. checkpoint: is the chain the one the operator signed and the witnesses cosigned
 *                 (deedlog checkpoint §2-§4, the C2SP signed-note and cosignature formats)?
 *
 * 1 and 2 are what an HMAC chain alone gives: someone who can write to the database and
 * read the HMAC key can rebuild both so that they pass. 3 is the part they cannot rebuild.
 */
final class IntegrityVerifier
{
    private PDO $db;
    private IntegrityChain $chain;

    /** @var list<string> */
    private array $failures = [];

    /** @var list<string> */
    private array $notes = [];

    public function __construct(PDO $db, IntegrityChain $chain)
    {
        $this->db = $db;
        $this->chain = $chain;
    }

    /** @return list<string> The chain's lines in order */
    public function lines(): array
    {
        return array_map('strval', $this->db->query('SELECT line FROM log_integrity_chain ORDER BY seq')->fetchAll(PDO::FETCH_COLUMN));
    }

    /** The newest checkpoint stored in the database, or null */
    public function storedCheckpoint(): ?string
    {
        $note = $this->db->query('SELECT note FROM log_integrity_checkpoints ORDER BY size DESC, id DESC LIMIT 1')->fetchColumn();

        return $note === false ? null : (string) $note;
    }

    /**
     * @param string|null $checkpoint The signed checkpoint to hold the chain to; null skips that part
     * @param string $operatorKey The operator's verifier key ("name+id+base64")
     * @param list<string> $witnessKeys The witnesses' verifier keys
     * @param bool $checkpointExpected Whether a missing checkpoint is a failure
     * @return array{ok: bool, lines: int, head: ?string, anchored: ?int, failures: list<string>, notes: list<string>}
     */
    public function verify(?string $checkpoint, string $operatorKey, array $witnessKeys, int $quorum, bool $checkpointExpected): array
    {
        $this->failures = [];
        $this->notes = [];

        $lines = $this->lines();
        $records = $this->checkChain($lines);
        if ($records !== null) {
            $this->checkRows($records);
        }

        $anchored = null;
        if ($checkpoint !== null) {
            $anchored = $this->checkCheckpoint($lines, $checkpoint, $operatorKey, $witnessKeys, $quorum);
        } elseif ($checkpointExpected) {
            $this->failures[] = 'checkpoint: none found, although an operator key is configured; without one, the chain is only as good as the database it is stored in';
        } else {
            $this->notes[] = 'checkpoint: none given; the chain was checked against itself only';
        }

        return [
            'ok' => $this->failures === [],
            'lines' => count($lines),
            'head' => $lines === [] ? null : 'sha256:' . hash('sha256', $lines[count($lines) - 1]),
            'anchored' => $anchored,
            'failures' => $this->failures,
            'notes' => $this->notes,
        ];
    }

    /**
     * deedlog evidence-chain §8.
     *
     * @param list<string> $lines
     * @return list<array<string, mixed>>|null The decoded records, or null when the chain itself is broken
     */
    private function checkChain(array $lines): ?array
    {
        if ($lines === []) {
            $this->failures[] = 'chain: no lines; nothing was recorded since logging.integrity_chain was turned on';
            return null;
        }

        $records = [];
        $name = null;
        foreach ($lines as $i => $line) {
            $record = json_decode($line, true);
            if (!is_array($record) || ($record['spec'] ?? null) !== IntegrityChain::SPEC) {
                $this->failures[] = sprintf('chain: line %d is not a %s record', $i, IntegrityChain::SPEC);
                return null;
            }
            $name ??= $record['chain'] ?? '';
            if ($name === '' || ($record['chain'] ?? null) !== $name) {
                $this->failures[] = sprintf('chain: line %d names a different chain', $i);
                return null;
            }
            if (($record['seq'] ?? null) !== $i) {
                $this->failures[] = sprintf('chain: line %d carries seq %s; a line was removed or reordered', $i, json_encode($record['seq'] ?? null));
                return null;
            }
            $expected = $i === 0 ? null : 'sha256:' . hash('sha256', $lines[$i - 1]);
            if (($record['prev'] ?? null) !== $expected) {
                $this->failures[] = sprintf('chain: line %d does not carry the hash of line %d; line %d was changed after it was written', $i, $i - 1, $i - 1);
                return null;
            }
            $digest = $record['subject']['digest'] ?? null;
            if (!is_array($digest) || $digest === []) {
                $this->failures[] = sprintf('chain: line %d has no subject digest', $i);
                return null;
            }
            $records[] = $record;
        }

        if ($this->chain->origin() !== '' && $name !== $this->chain->origin()) {
            $this->failures[] = sprintf('chain: it is named "%s", the settings name "%s"', $name, $this->chain->origin());
        }

        return $records;
    }

    /**
     * Folds the chain into what each table should hold now, then compares with the tables.
     *
     * @param list<array<string, mixed>> $records
     */
    private function checkRows(array $records): void
    {
        $baseline = [];
        $pruned = [];
        $expected = [];
        foreach (array_keys(IntegrityChain::TABLES) as $table) {
            $baseline[$table] = 0;
            $pruned[$table] = [0, null];
            $expected[$table] = [];
        }

        foreach ($records as $seq => $record) {
            $meta = is_array($record['meta'] ?? null) ? $record['meta'] : [];
            $table = $meta['table'] ?? null;
            switch ($meta['event'] ?? '') {
                case IntegrityChain::EVENT_OPENED:
                    foreach (array_keys(IntegrityChain::TABLES) as $t) {
                        $baseline[$t] = (int) ($meta['baseline.' . $t] ?? 0);
                    }
                    break;
                case IntegrityChain::EVENT_ROW_WRITTEN:
                case IntegrityChain::EVENT_ROW_ANONYMIZED:
                    if (isset($expected[$table])) {
                        $expected[$table][(int) $meta['id']] = [$record['subject']['digest']['hmac-sha256'] ?? '', $meta['key'] ?? '', $seq];
                    }
                    break;
                case IntegrityChain::EVENT_ROWS_PRUNED:
                    if (isset($pruned[$table]) && (int) $meta['through_id'] > $pruned[$table][0]) {
                        $pruned[$table] = [(int) $meta['through_id'], $seq];
                    }
                    break;
            }
        }

        $keyId = $this->chain->keyId();
        foreach (IntegrityChain::TABLES as $table => $columns) {
            $checked = 0;
            $otherKey = 0;
            $old = 0;
            $seen = [];
            $stmt = $this->db->query('SELECT ' . implode(', ', $columns) . ' FROM ' . $table . ' ORDER BY id');
            while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
                $id = (int) $row['id'];
                $seen[$id] = true;
                if ($id <= $baseline[$table]) {
                    $old++;
                    continue;
                }
                if ($id <= $pruned[$table][0]) {
                    $this->failures[] = sprintf('rows: %s id %d is present, but line %d says every row up to id %d was pruned', $table, $id, $pruned[$table][1], $pruned[$table][0]);
                    continue;
                }
                if (!isset($expected[$table][$id])) {
                    $this->failures[] = sprintf('rows: %s id %d has no line in the chain; it was not written by the application', $table, $id);
                    continue;
                }
                [$digest, $key, $seq] = $expected[$table][$id];
                if ($key !== $keyId) {
                    $otherKey++;
                    continue;
                }
                if (!hash_equals($digest, $this->chain->digest(IntegrityChain::bodyOf($table, $row)))) {
                    $this->failures[] = sprintf('rows: %s id %d differs from what line %d recorded; the row was changed after it was written', $table, $id, $seq);
                    continue;
                }
                $checked++;
            }

            foreach ($expected[$table] as $id => [, , $seq]) {
                if (!isset($seen[$id]) && $id > $pruned[$table][0]) {
                    $this->failures[] = sprintf('rows: %s id %d is gone, but line %d recorded it and no line says it was pruned', $table, $id, $seq);
                }
            }

            $summary = sprintf('rows: %s: %d match the chain', $table, $checked);
            if ($pruned[$table][0] > 0) {
                $summary .= sprintf(', rows up to id %d pruned (line %d)', $pruned[$table][0], $pruned[$table][1]);
            }
            if ($old > 0) {
                $summary .= sprintf(', %d older than the chain and not covered', $old);
            }
            if ($otherKey > 0) {
                $summary .= sprintf(', %d not checked (recorded under another HMAC key)', $otherKey);
            }
            $this->notes[] = $summary;
        }
    }

    /**
     * @param list<string> $lines
     * @param list<string> $witnessKeys
     * @return int|null The number of lines the checkpoint covers, when it could be read
     */
    private function checkCheckpoint(array $lines, string $checkpoint, string $operatorKey, array $witnessKeys, int $quorum): ?int
    {
        $parts = explode("\n\n", $checkpoint, 2);
        $text = $parts[0] . "\n";
        $body = explode("\n", $parts[0]);
        if (count($parts) !== 2 || count($body) !== 3 || preg_match('/^(0|[1-9][0-9]*)$/', $body[1]) !== 1) {
            $this->failures[] = 'checkpoint: not a signed checkpoint (origin, size and root hash, then signatures)';
            return null;
        }
        [$origin, $size, $root] = [$body[0], (int) $body[1], $body[2]];

        if ($lines !== [] && $origin !== (json_decode($lines[0], true)['chain'] ?? null)) {
            $this->failures[] = sprintf('checkpoint: it is for "%s", not for this chain', $origin);
            return $size;
        }

        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            $this->failures[] = 'checkpoint: the signatures were not checked: PHP has no sodium extension (use "dlog verify" on the exported chain instead)';
        } elseif ($operatorKey === '') {
            $this->failures[] = 'checkpoint: the signatures were not checked: no operator key given (logging.integrity_chain_operator_key or --operator-key)';
        } else {
            $signatures = self::signatures($parts[1]);
            if (!self::signedBy($operatorKey, 0x01, $text, $signatures)) {
                $this->failures[] = 'checkpoint: it does not carry a valid signature of the operator key';
            }
            $cosigned = 0;
            foreach ($witnessKeys as $witnessKey) {
                if (self::signedBy($witnessKey, 0x04, $text, $signatures)) {
                    $cosigned++;
                }
            }
            if ($cosigned < $quorum) {
                $this->failures[] = sprintf('checkpoint: %d of the %d configured witnesses cosigned it, %d needed', $cosigned, count($witnessKeys), $quorum);
            } else {
                $this->notes[] = sprintf('checkpoint: signed by the operator, cosigned by %d of %d configured witnesses', $cosigned, count($witnessKeys));
            }
        }

        if ($size > count($lines)) {
            $this->failures[] = sprintf('checkpoint: it covers %d lines, the chain has %d; lines were removed from the end', $size, count($lines));
            return $size;
        }
        if (base64_encode(self::merkleRoot(array_slice($lines, 0, $size))) !== $root) {
            $this->failures[] = sprintf('checkpoint: the first %d lines are not the ones that were signed and cosigned; the chain was rewritten', $size);
            return $size;
        }

        $this->notes[] = sprintf('checkpoint: the first %d of %d lines are exactly what was signed', $size, count($lines));
        if ($size < count($lines)) {
            $this->notes[] = sprintf('checkpoint: %d newer lines are not covered by a checkpoint yet', count($lines) - $size);
        }

        return $size;
    }

    /**
     * The Merkle tree hash of RFC 6962 §2.1 over the lines' bytes.
     *
     * @param list<string> $lines
     */
    public static function merkleRoot(array $lines): string
    {
        if ($lines === []) {
            return hash('sha256', '', true);
        }

        // A stack of [hash, height]: two subtrees of the same height are merged as soon as they meet
        $stack = [];
        foreach ($lines as $line) {
            $node = [hash('sha256', "\x00" . $line, true), 0];
            while ($stack !== [] && $stack[count($stack) - 1][1] === $node[1]) {
                $left = array_pop($stack);
                $node = [hash('sha256', "\x01" . $left[0] . $node[0], true), $node[1] + 1];
            }
            $stack[] = $node;
        }

        $root = array_pop($stack)[0];
        while ($stack !== []) {
            $root = hash('sha256', "\x01" . array_pop($stack)[0] . $root, true);
        }

        return $root;
    }

    /**
     * The signature lines of a signed note: "— <name> <base64 of key id and signature>".
     *
     * @return list<array{0: string, 1: string}> Pairs of key name and raw signature bytes
     */
    private static function signatures(string $block): array
    {
        $signatures = [];
        foreach (explode("\n", trim($block)) as $line) {
            if (preg_match('/^\x{2014} (\S+) (\S+)$/u', $line, $m) === 1) {
                $raw = base64_decode($m[2], true);
                if ($raw !== false) {
                    $signatures[] = [$m[1], $raw];
                }
            }
        }

        return $signatures;
    }

    /**
     * Whether one of the signatures is by the given verifier key. Type 0x01 is an Ed25519
     * signature over the note text; type 0x04 is a timestamped cosignature
     * (c2sp.org/tlog-cosignature) over "cosignature/v1\ntime <t>\n" and the note text.
     *
     * @param list<array{0: string, 1: string}> $signatures
     */
    private static function signedBy(string $verifierKey, int $type, string $text, array $signatures): bool
    {
        // The base64 part may itself contain "+"
        $parts = explode('+', trim($verifierKey), 3);
        $key = count($parts) === 3 ? base64_decode($parts[2], true) : false;
        if ($key === false || strlen($key) !== 33 || ord($key[0]) !== $type) {
            return false;
        }
        $public = substr($key, 1);
        $keyId = substr(hash('sha256', $parts[0] . "\n" . chr($type) . $public, true), 0, 4);

        foreach ($signatures as [$name, $raw]) {
            if ($name !== $parts[0] || substr($raw, 0, 4) !== $keyId) {
                continue;
            }
            if ($type === 0x01 && strlen($raw) === 68) {
                return sodium_crypto_sign_verify_detached(substr($raw, 4), $text, $public);
            }
            if ($type === 0x04 && strlen($raw) === 76) {
                $time = unpack('J', substr($raw, 4, 8))[1];
                return sodium_crypto_sign_verify_detached(substr($raw, 12), "cosignature/v1\ntime " . $time . "\n" . $text, $public);
            }
        }

        return false;
    }
}
