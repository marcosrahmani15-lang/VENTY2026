import { isPostgresConfigured } from './client';
import { runMigrations } from './migrations';
import { migrateJsonToPostgres } from './migrateData';

async function main() {
  console.log('========================================================');
  console.log('VENTY THE COFFEE — PostgreSQL Serverless Migration CLI');
  console.log('========================================================');

  if (!isPostgresConfigured()) {
    console.error('ERROR: DATABASE_URL environment variable is not set.');
    console.error('Please configure DATABASE_URL (e.g. from Neon Postgres) before running this script.');
    process.exit(1);
  }

  try {
    console.log('Step 1: Running DDL schema migrations...');
    const migRes = await runMigrations();
    console.log(`✓ ${migRes.message}`);

    console.log('\nStep 2: Migrating existing data from data_store/venty_loyalty_db.json...');
    const dataRes = await migrateJsonToPostgres();
    console.log(`✓ Data migration completed in ${dataRes.durationMs}ms`);
    console.log(`  - Customers: ${dataRes.customersCount}`);
    console.log(`  - Orders: ${dataRes.ordersCount}`);
    console.log(`  - Order Items: ${dataRes.orderItemsCount}`);
    console.log(`  - Transactions: ${dataRes.transactionsCount}`);
    console.log(`  - Rewards: ${dataRes.rewardsCount}`);
    console.log(`  - Store Settings: ${dataRes.settingsCount}`);

    console.log('\n========================================================');
    console.log('MIGRATION COMPLETED SUCCESSFULLY!');
    console.log('PostgreSQL database is now durable, normalized, and Vercel-ready.');
    console.log('========================================================');
  } catch (err: any) {
    console.error('FATAL: Database migration failed:', err?.message || err);
    process.exit(1);
  }
}

main();
