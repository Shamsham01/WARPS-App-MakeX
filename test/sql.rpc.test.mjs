import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const migrationsDir = path.join(root, 'supabase', 'migrations');
const container = `makex-tx-rpc-${process.pid}`;

function docker(args, input) {
  const result = spawnSync('docker', args, {
    input,
    encoding: 'utf8',
    timeout: 120000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || `docker exited ${result.status}`).trim());
  }
  return (result.stdout || '').trim();
}

function psql(sql) {
  return docker(['exec', '-i', container, 'psql', '-U', 'postgres', '-d', 'makex_tx', '-v', 'ON_ERROR_STOP=1', '-t', '-A'], sql);
}

function query(sql) {
  const raw = psql(sql);
  return raw ? JSON.parse(raw) : null;
}

test('coordinator RPC functions enforce idempotency, one unresolved nonce, and service-role grants', async () => {
  docker(['run', '-d', '--name', container, '-e', 'POSTGRES_PASSWORD=postgres', '-e', 'POSTGRES_DB=makex_tx', 'postgres:16']);
  try {
    const readyDeadline = Date.now() + 40000;
    let readyError = 'postgres did not accept connections';
    let ready = false;
    while (Date.now() < readyDeadline) {
      const probe = spawnSync('docker', ['exec', container, 'psql', '-U', 'postgres', '-d', 'makex_tx', '-c', 'select 1'], { encoding: 'utf8' });
      if (probe.status === 0) {
        ready = true;
        break;
      }
      readyError = (probe.stderr || probe.stdout || probe.error?.message || 'postgres is starting').trim();
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    assert.equal(ready, true, readyError);

    psql(`
      do $$ begin
        if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
        if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
        if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
      end $$;
    `);
    for (const file of readdirSync(migrationsDir).filter((name) => name.endsWith('.sql')).sort()) {
      psql(readFileSync(path.join(migrationsDir, file), 'utf8'));
    }

    const health = query(`select public.makex_tx_health();`);
    assert.equal(health.ok, true);
    assert.equal(health.version, 1);

    const created = query(`
      select public.makex_tx_begin_operation('same-key', 'fingerprint-a', 'makex-transfers', '1', 'erd1wallet');
    `);
    assert.equal(created.ok, true);
    assert.equal(created.created, true);
    const operationId = created.operation.id;

    const replay = query(`
      select public.makex_tx_begin_operation('same-key', 'fingerprint-a', 'makex-transfers', '1', 'erd1wallet');
    `);
    assert.equal(replay.created, false);
    assert.equal(replay.operation.id, operationId);

    const conflict = query(`
      select public.makex_tx_begin_operation('same-key', 'fingerprint-b', 'makex-transfers', '1', 'erd1wallet');
    `);
    assert.equal(conflict.ok, false);
    assert.equal(conflict.reason, 'fingerprint_mismatch');

    const separate = query(`
      select public.makex_tx_begin_operation('other-key', 'fingerprint-a', 'makex-transfers', '1', 'erd1wallet');
    `);
    assert.equal(separate.created, true);

    const lease = query(`
      select public.makex_tx_acquire_lease('1', 'erd1wallet', 'tester', 60000);
    `);
    assert.equal(lease.acquired, true);
    const token = lease.fencingToken;

    const reserved = query(`
      select public.makex_tx_reserve_nonce(
        '1', 'erd1wallet', 'tester', ${token}, 5, '${operationId}'::uuid, 'makex-transfers', 'fee', 'fingerprint-a'
      );
    `);
    assert.equal(reserved.ok, true);
    assert.equal(Number(reserved.reservation.nonce), 5);
    const reservationId = reserved.reservation.id;

    const blocked = query(`
      select public.makex_tx_reserve_nonce(
        '1', 'erd1wallet', 'tester', ${token}, 5, '${operationId}'::uuid, 'makex-transfers', 'primary', 'fingerprint-a'
      );
    `);
    assert.equal(blocked.ok, false);
    assert.equal(blocked.reason, 'unresolved');

    const signed = query(`
      select public.makex_tx_save_signed(
        '${reservationId}'::uuid, 'tester', ${token}, 'abc123', '{"nonce":5}'::jsonb
      );
    `);
    assert.equal(signed.ok, true);
    assert.equal(signed.reservation.state, 'SIGNED');

    const confirmed = query(`
      select public.makex_tx_transition_reservation(
        '${reservationId}'::uuid, 'tester', ${token}, 'CONFIRMED', null, null, null, 'abc123', null
      );
    `);
    assert.equal(confirmed.ok, true);
    assert.equal(confirmed.reservation.state, 'CONFIRMED');

    const recorded = query(`
      select public.makex_tx_update_operation(
        '${operationId}'::uuid,
        '{"state":"OPERATION_CONFIRMED","fee_tx_hash":"abc123","http_status":200}'::jsonb,
        null
      );
    `);
    assert.equal(recorded.ok, true);
    assert.equal(recorded.operation.state, 'OPERATION_CONFIRMED');
    assert.equal(recorded.operation.fee_tx_hash, 'abc123');

    const claimable = query(`
      select public.makex_tx_begin_operation('claim-key', 'fingerprint-a', 'makex-transfers', '1', 'erd1wallet');
    `);
    const claimId = claimable.operation.id;
    query(`
      select public.makex_tx_update_operation(
        '${claimId}'::uuid,
        '{"state":"FEE_CONFIRMED","fee_tx_hash":"fee-hash"}'::jsonb,
        null
      );
    `);
    const firstClaim = query(`select public.makex_tx_claim_business('${claimId}'::uuid, 'owner-a', 60000);`);
    assert.equal(firstClaim.claimed, true);
    assert.equal(firstClaim.operation.state, 'OPERATION_IN_PROGRESS');
    const secondClaim = query(`select public.makex_tx_claim_business('${claimId}'::uuid, 'owner-b', 60000);`);
    assert.equal(secondClaim.claimed, false);
    assert.equal(secondClaim.reason, 'in_progress');
    psql(`update public.makex_operations set claim_expires_at = now() - interval '1 minute' where id = '${claimId}';`);
    const reclaimed = query(`select public.makex_tx_claim_business('${claimId}'::uuid, 'owner-b', 60000);`);
    assert.equal(reclaimed.claimed, true);
    const pending = query(`
      select public.makex_tx_update_operation(
        '${claimId}'::uuid,
        '{"state":"OPERATION_PENDING","error_class":"business_pending"}'::jsonb,
        'OPERATION_IN_PROGRESS'
      );
    `);
    assert.equal(pending.ok, true);
    assert.equal(pending.operation.state, 'OPERATION_PENDING');
    const confirmedClaim = query(`select public.makex_tx_claim_business('${operationId}'::uuid, 'owner-c', 60000);`);
    assert.equal(confirmedClaim.claimed, false);
    assert.equal(confirmedClaim.reason, 'confirmed');

    const anonDenied = spawnSync(
      'docker',
      ['exec', '-i', container, 'psql', '-U', 'postgres', '-d', 'makex_tx', '-v', 'ON_ERROR_STOP=1', '-c',
        'set role anon; select count(*) from public.makex_operations;'],
      { encoding: 'utf8' },
    );
    assert.notEqual(anonDenied.status, 0);
    assert.match(`${anonDenied.stderr}`, /permission denied/i);
  } finally {
    spawnSync('docker', ['rm', '-f', container], { encoding: 'utf8' });
  }
});
