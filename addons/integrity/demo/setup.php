<?php

// Creates the demo's SQLite database (PowerDNS and Poweradmin schema, one administrator) and
// its settings file, with logging.integrity_chain on.
//
//   php setup.php <work directory> <chain origin>

[$work, $origin] = [$argv[1], $argv[2]];
$root = dirname(__DIR__, 3);

@unlink("$work/pdns.db");
$db = new PDO("sqlite:$work/pdns.db");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec(file_get_contents("$root/sql/pdns/49/schema.sqlite3.sql"));
$db->exec(file_get_contents("$root/sql/poweradmin-sqlite-db-structure.sql"));
$db->prepare("INSERT INTO users (username, password, fullname, email, description, perm_templ, active, use_ldap)
              VALUES ('admin', ?, 'Administrator', 'admin@example.net', 'System Administrator', 1, 1, 0)")
    ->execute([password_hash('demo-admin-pass', PASSWORD_DEFAULT)]);

// The HMAC key lives in a file the database account cannot read; here, just outside the database
file_put_contents("$work/hmac.key", bin2hex(random_bytes(32)) . "\n");

$settings = [
    'database' => ['type' => 'sqlite', 'file' => "$work/pdns.db"],
    'security' => ['session_key' => bin2hex(random_bytes(32))],
    'interface' => ['language' => 'en_EN'],
    'dns' => ['hostmaster' => 'hostmaster.example.net', 'ns1' => 'ns1.example.net', 'ns2' => 'ns2.example.net'],
    'logging' => [
        'database_enabled' => true,
        'integrity_chain' => true,
        'integrity_chain_origin' => $origin,
        'integrity_chain_key_file' => "$work/hmac.key",
        'integrity_chain_operator_key' => trim(file_get_contents("$work/operator.vkey")),
        'integrity_chain_witness_keys' => [trim(file_get_contents("$work/witness.vkey"))],
    ],
];
file_put_contents("$work/settings.php", "<?php\n\nreturn " . var_export($settings, true) . ";\n");
