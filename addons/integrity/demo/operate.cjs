// Drives the Poweradmin web interface for the integrity-chain demo, so that the log rows
// are written by the application itself. Needs Playwright (require('playwright')).
//
//   node operate.cjs <base url> <scene> [screenshot directory]
//
// Scenes: "first" (an administrator adds a user, a zone and a record and changes the record;
// the new user signs in and adds another record), "more" (one more record).
const { chromium } = require('playwright');

const [base, scene, shots] = process.argv.slice(2);
const ADMIN = ['admin', 'demo-admin-pass'];
const TANAKA = ['tanaka', 'Demo-tanaka-pass-1'];

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const submit = (selector) => Promise.all([page.waitForLoadState('networkidle'), page.click(selector)]);
  const said = async (what) => {
    const alerts = await page.$$eval('.alert', (es) => es.map((e) => e.innerText.trim().replace(/\s+/g, ' ')).join(' / '));
    console.log(`${what}: ${alerts || page.url()}`);
    if (/error/i.test(alerts)) throw new Error(`${what} failed: ${alerts}`);
  };
  const login = async ([user, password]) => {
    await page.goto(`${base}/login`);
    await page.fill('input[name=username]', user);
    await page.fill('input[name=password]', password);
    await submit('button[type=submit]');
    if (page.url().includes('/login')) throw new Error(`login as ${user} failed`);
    console.log(`signed in as ${user}`);
  };
  const logout = async () => { await page.goto(`${base}/logout`); };
  const zoneId = async (name) => {
    await page.goto(`${base}/zones/forward`);
    const href = await page.$$eval('a[href]', (as, n) => {
      const row = as.find((a) => /\/zones\/\d+\/edit$/.test(a.getAttribute('href')) && a.closest('tr')?.innerText.includes(n));
      return row ? row.getAttribute('href') : null;
    }, name);
    if (!href) throw new Error(`zone ${name} not found`);
    return href.match(/\/zones\/(\d+)\//)[1];
  };
  const addRecord = async (zone, name, content) => {
    await page.goto(`${base}/zones/${zone}/records/add`);
    await page.fill('input[name="records[0][name]"]', name);
    await page.selectOption('select[name="records[0][type]"]', 'A');
    await page.fill('input[name="records[0][content]"]', content);
    await submit('button[name=commit]');
    await said(`record ${name} A ${content}`);
  };

  if (scene === 'first') {
    await login(ADMIN);
    await page.goto(`${base}/users/add`);
    await page.fill('input[name=username]', TANAKA[0]);
    await page.fill('input[name=fullname]', 'Tanaka (demo)');
    await page.fill('input[name=email]', 'tanaka@example.net');
    await page.fill('input[name=password]', TANAKA[1]);
    await page.selectOption('select[name=perm_templ]', { label: 'Administrator' });
    await submit('button[name=commit]');
    await said('user tanaka');

    await page.goto(`${base}/zones/add/master`);
    await page.fill('input[name=domain]', 'example.net');
    await submit('button[name=submit]');
    await said('zone example.net');

    const zone = await zoneId('example.net');
    await addRecord(zone, 'www', '192.0.2.10');

    await page.goto(`${base}/zones/${zone}/edit`);
    const rid = await page.$$eval('input[name^="record["][name$="[name]"]', (inputs) => {
      const input = inputs.find((i) => i.value.startsWith('www'));
      return input ? input.name.match(/record\[(\d+)\]/)[1] : null;
    });
    await page.goto(`${base}/zones/${zone}/records/${rid}/edit`);
    await page.fill('input[name=content]', '192.0.2.20');
    await submit('button[name=commit]');
    await said('record www changed to 192.0.2.20');
    await logout();

    await login(TANAKA);
    await addRecord(zone, 'mail', '192.0.2.30');
    await logout();
  } else if (scene === 'more') {
    await login(ADMIN);
    await addRecord(await zoneId('example.net'), 'api', '192.0.2.40');
    await logout();
  } else if (scene === 'shots') {
    await login(ADMIN);
    for (const [path, file] of [['/users/logs', 'log-users.png'], ['/zones/changes', 'record-changes.png']]) {
      await page.goto(`${base}${path}`);
      await page.screenshot({ path: `${shots}/${file}` });
    }
    await logout();
  } else {
    throw new Error('scene must be first, more or shots');
  }
  await browser.close();
})().catch((error) => { console.error(error.message); process.exit(1); });
