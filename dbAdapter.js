const createDbAdapter = (pool) => {
    const ensureBillingTables = async () => {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS org_billing (
                org_id INTEGER PRIMARY KEY,
                stripe_customer_id TEXT UNIQUE,
                stripe_subscription_id TEXT,
                plan TEXT,
                subscription_status TEXT,
                current_period_end TIMESTAMPTZ
            );
            CREATE TABLE IF NOT EXISTS stripe_events (
                event_id TEXT PRIMARY KEY,
                processed_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
    };

    const getBillingStatusByOrgId = async (orgId) => {
        const { rows } = await pool.query(
            `
            SELECT plan, subscription_status, current_period_end, stripe_customer_id, stripe_subscription_id
            FROM org_billing
            WHERE org_id = $1
            `,
            [orgId]
        );
        return rows[0] || null;
    };

    const upsertBillingForOrg = async (orgId, data) => {
        const values = [
            orgId,
            data.stripe_customer_id ?? null,
            data.stripe_subscription_id ?? null,
            data.plan ?? null,
            data.subscription_status ?? null,
            data.current_period_end ?? null
        ];

        await pool.query(
            `
            INSERT INTO org_billing (
                org_id,
                stripe_customer_id,
                stripe_subscription_id,
                plan,
                subscription_status,
                current_period_end
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (org_id) DO UPDATE SET
                stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, org_billing.stripe_customer_id),
                stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, org_billing.stripe_subscription_id),
                plan = COALESCE(EXCLUDED.plan, org_billing.plan),
                subscription_status = COALESCE(EXCLUDED.subscription_status, org_billing.subscription_status),
                current_period_end = COALESCE(EXCLUDED.current_period_end, org_billing.current_period_end)
            `,
            values
        );
    };

    const getOrgIdByCustomerId = async (customerId) => {
        const { rows } = await pool.query(
            "SELECT org_id FROM org_billing WHERE stripe_customer_id = $1",
            [customerId]
        );
        return rows[0]?.org_id || null;
    };

    const isStripeEventProcessed = async (eventId) => {
        const { rows } = await pool.query(
            "SELECT event_id FROM stripe_events WHERE event_id = $1",
            [eventId]
        );
        return rows.length > 0;
    };

    const markStripeEventProcessed = async (eventId) => {
        await pool.query(
            "INSERT INTO stripe_events (event_id) VALUES ($1) ON CONFLICT DO NOTHING",
            [eventId]
        );
    };

    return {
        ensureBillingTables,
        getBillingStatusByOrgId,
        upsertBillingForOrg,
        getOrgIdByCustomerId,
        isStripeEventProcessed,
        markStripeEventProcessed
    };
};

module.exports = { createDbAdapter };
