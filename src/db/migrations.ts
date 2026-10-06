import { query, transaction, isPostgresConfigured } from './client';
import { SCHEMA_SQL } from './schema';

export const runMigrations = async (): Promise<{ success: boolean; message: string }> => {
  if (!isPostgresConfigured()) {
    return {
      success: false,
      message: 'DATABASE_URL is not configured; skipping Postgres migrations.',
    };
  }

  try {
    console.log('[Postgres Migration] Initializing normalized relational schema...');
    
    // Execute DDL schema inside transaction
    await transaction(async (client) => {
      // Create migration metadata table
      await client.query(`
        CREATE TABLE IF NOT EXISTS _schema_migrations (
          id SERIAL PRIMARY KEY,
          version VARCHAR(64) NOT NULL UNIQUE,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Check if v1_initial_schema has already been applied
      const checkRes = await client.query(
        `SELECT id FROM _schema_migrations WHERE version = $1`,
        ['v1_initial_schema'],
      );

      if (checkRes.rows.length === 0) {
        // Execute DDL schema
        await client.query(SCHEMA_SQL);
        await client.query(
          `INSERT INTO _schema_migrations (version) VALUES ($1)`,
          ['v1_initial_schema'],
        );
        console.log('[Postgres Migration] Applied v1_initial_schema successfully.');
      } else {
        console.log('[Postgres Migration] Schema v1_initial_schema already up to date.');
      }
    });

    return {
      success: true,
      message: 'Postgres migrations applied successfully.',
    };
  } catch (err: any) {
    console.error('[Postgres Migration Error] Failed to run migrations:', err?.message || err);
    throw err;
  }
};
