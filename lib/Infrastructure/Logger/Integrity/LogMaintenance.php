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
use RuntimeException;

/**
 * Pruning and anonymising log rows in a way the integrity chain can follow: the rows change,
 * the chain is not re-built, and a line saying what was done is appended.
 *
 * These are small stand-ins for the retention CLI of issue 1172 and the anonymisation of
 * issue 1861, enough to show how either would meet the chain. They are not those features.
 */
final class LogMaintenance
{
    private PDO $db;
    private IntegrityChain $chain;

    public function __construct(PDO $db, IntegrityChain $chain)
    {
        $this->db = $db;
        $this->chain = $chain;
    }

    /**
     * Deletes the rows of one log table written before $cutoff ("Y-m-d H:i:s", UTC, as
     * DbApiLogger::pruneOlderThan() compares).
     *
     * @return int The number of rows deleted
     */
    public function prune(string $table, string $cutoff, string $reason): int
    {
        if (!isset(IntegrityChain::TABLES[$table])) {
            throw new RuntimeException(sprintf('"%s" is not a log table', $table));
        }

        return $this->atomically(function () use ($table, $cutoff, $reason): int {
            $stmt = $this->db->prepare('SELECT MAX(id) FROM ' . $table . ' WHERE created_at < :cutoff');
            $stmt->execute([':cutoff' => $cutoff]);
            $throughId = (int) $stmt->fetchColumn();
            if ($throughId === 0) {
                return 0;
            }

            // Ids grow with time, so "older than the cutoff" is stated as one id: a single line covers the whole run
            $stmt = $this->db->prepare('DELETE FROM ' . $table . ' WHERE id <= :through');
            $stmt->execute([':through' => $throughId]);
            $count = $stmt->rowCount();
            if ($this->chain->isEnabled()) {
                $this->chain->rowsPruned($table, $throughId, $count, $reason);
            }

            return $count;
        });
    }

    /**
     * Replaces a user's name and client address in the log rows that carry them.
     *
     * @return int The number of rows rewritten
     */
    public function anonymizeUser(string $username, string $replacement): int
    {
        if (preg_match('/^[^\s%_]+$/', $username) !== 1) {
            throw new RuntimeException('The user name must not contain spaces, "%" or "_"');
        }

        return $this->atomically(function () use ($username, $replacement): int {
            $changed = 0;

            foreach (['log_users', 'log_zones', 'log_groups', 'log_api'] as $table) {
                $stmt = $this->db->prepare('SELECT id, event FROM ' . $table . ' WHERE event LIKE :needle ORDER BY id');
                $stmt->execute([':needle' => '%' . $username . '%']);
                foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                    $name = preg_quote($username, '/');
                    // "user:" is who acted, and the client address on that line is theirs;
                    // "username:" is who was acted upon, next to their e-mail address
                    $event = preg_replace('/\buser:' . $name . '(?=\s|$)/', 'user:' . $replacement, (string) $row['event'], -1, $asActor);
                    $event = preg_replace('/\busername:' . $name . '(?=\s|$)/', 'username:' . $replacement, (string) $event, -1, $asSubject);
                    if ($asActor + $asSubject === 0) {
                        continue;
                    }
                    if ($asActor > 0) {
                        $event = preg_replace('/\bclient_ip:\S*/', 'client_ip:', (string) $event);
                    }
                    if ($asSubject > 0) {
                        $event = preg_replace('/\bemail:\S*/', 'email:', (string) $event);
                    }
                    $update = $this->db->prepare('UPDATE ' . $table . ' SET event = :event WHERE id = :id');
                    $update->execute([':event' => $event, ':id' => $row['id']]);
                    $changed += $this->recordAnonymized($table, (int) $row['id']);
                }
            }

            foreach (['log_changesets', 'log_record_changes'] as $table) {
                $stmt = $this->db->prepare('SELECT id FROM ' . $table . ' WHERE username = :username ORDER BY id');
                $stmt->execute([':username' => $username]);
                foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $id) {
                    $update = $this->db->prepare('UPDATE ' . $table . " SET username = :replacement, client_ip = '' WHERE id = :id");
                    $update->execute([':replacement' => $replacement, ':id' => $id]);
                    $changed += $this->recordAnonymized($table, (int) $id);
                }
            }

            return $changed;
        });
    }

    private function recordAnonymized(string $table, int $id): int
    {
        if ($this->chain->isEnabled()) {
            $this->chain->rowAnonymized($table, $id, 'user deleted');
        }

        return 1;
    }

    /** The rows and the line that accounts for them change together or not at all */
    private function atomically(callable $work): int
    {
        $own = !$this->db->inTransaction();
        if ($own) {
            $this->db->beginTransaction();
        }
        try {
            $result = $work();
            if ($own) {
                $this->db->commit();
            }

            return $result;
        } catch (\Throwable $e) {
            if ($own) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }
}
