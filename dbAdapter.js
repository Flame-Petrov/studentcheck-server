// Billing storage. The billing "org" is the teacher: orgId is the teacher's user id.
const createDbAdapter = (pool) => {
    const getBillingStatusByOrgId = async (orgId) => {
        const { rows } = await pool.query(
            `
            SELECT plan, subscription_status, current_period_end, stripe_customer_id, stripe_subscription_id
            FROM billing_accounts
            WHERE teacher_id = $1
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
            INSERT INTO billing_accounts (
                teacher_id,
                stripe_customer_id,
                stripe_subscription_id,
                plan,
                subscription_status,
                current_period_end
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (teacher_id) DO UPDATE SET
                stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, billing_accounts.stripe_customer_id),
                stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, billing_accounts.stripe_subscription_id),
                plan = COALESCE(EXCLUDED.plan, billing_accounts.plan),
                subscription_status = COALESCE(EXCLUDED.subscription_status, billing_accounts.subscription_status),
                current_period_end = COALESCE(EXCLUDED.current_period_end, billing_accounts.current_period_end),
                updated_at = NOW()
            `,
            values
        );
    };

    const getOrgIdByCustomerId = async (customerId) => {
        const { rows } = await pool.query(
            "SELECT teacher_id FROM billing_accounts WHERE stripe_customer_id = $1",
            [customerId]
        );
        return rows[0]?.teacher_id || null;
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
        getBillingStatusByOrgId,
        upsertBillingForOrg,
        getOrgIdByCustomerId,
        isStripeEventProcessed,
        markStripeEventProcessed
    };
};

module.exports = { createDbAdapter };
