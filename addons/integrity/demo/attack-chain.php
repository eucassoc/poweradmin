<?php

// The attacker of scene 3: has the database credentials and the HMAC key. Rewrites the same
// rows as attack-rows.php, then repairs the chain: a fresh HMAC for each rewritten row, and a
// fresh "prev" hash for every line after it. Also removes the stored checkpoints.
//
//   php attack-chain.php <database file> <HMAC key file>

require dirname(__DIR__, 3) . '/vendor/autoload.php';

use Poweradmin\Infrastructure\Logger\Integrity\IntegrityChain;

$db = new PDO('sqlite:' . $argv[1]);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$key = trim(file_get_contents($argv[2]));

$db->exec("UPDATE log_zones SET event = replace(event, 'user:tanaka', 'user:admin') WHERE event LIKE '%user:tanaka%record:mail.example.net%'");
$db->exec("UPDATE log_record_changes SET username = 'admin', user_id = 1 WHERE username = 'tanaka'");

$encode = static fn(array $record): string => json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$previous = null;
$rewritten = 0;
foreach ($db->query('SELECT seq, line FROM log_integrity_chain ORDER BY seq')->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $record = json_decode($row['line'], true);
    $meta = $record['meta'];
    if (isset($meta['table'], $meta['id'], $record['subject']['digest']['hmac-sha256'])) {
        $body = IntegrityChain::rowBody($db, $meta['table'], (int) $meta['id']);
        if ($body !== null) {
            $record['subject']['size'] = strlen($body);
            $record['subject']['digest']['hmac-sha256'] = hash_hmac('sha256', $body, $key);
        }
    }
    if ($previous !== null) {
        $record['prev'] = 'sha256:' . hash('sha256', $previous);
    }
    $line = $encode($record);
    if ($line !== $row['line']) {
        $db->prepare('UPDATE log_integrity_chain SET line = ? WHERE seq = ?')->execute([$line, $row['seq']]);
        $rewritten++;
    }
    $previous = $line;
}
$db->exec('DELETE FROM log_integrity_checkpoints');
echo "rewrote the log rows, repaired $rewritten chain lines with the HMAC key, deleted the stored checkpoints\n";
