<?php

// Removes the newest log row and its chain line, as if the last thing had never happened.
//
//   php attack-truncate.php <database file>

$db = new PDO('sqlite:' . $argv[1]);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$last = json_decode($db->query('SELECT line FROM log_integrity_chain ORDER BY seq DESC LIMIT 1')->fetchColumn(), true);
$db->prepare('DELETE FROM ' . $last['meta']['table'] . ' WHERE id = ?')->execute([$last['meta']['id']]);
$db->prepare('DELETE FROM log_integrity_chain WHERE seq = ?')->execute([$last['seq']]);
echo "deleted {$last['meta']['table']} id {$last['meta']['id']} and chain line {$last['seq']}\n";
