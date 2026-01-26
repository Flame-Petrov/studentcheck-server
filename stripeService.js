const DEFAULT_PLAN_BY_PRICE_ID = {};

const createStripeService = ({ stripe, db, appUrl, priceIdToPlan = DEFAULT_PLAN_BY_PRICE_ID }) => {
    if (!stripe) {
        throw new Error("Stripe client is required");
    }
    if (!db) {
        throw new Error("DB adapter is required");
    }

    const getBillingStatus = async (orgId, canManageBilling) => {
        const billing = await db.getBillingStatusByOrgId(orgId);
        return {
            plan: billing?.plan || "free",
            subscription_status: billing?.subscription_status || "inactive",
            current_period_end: billing?.current_period_end || null,
            can_manage_billing: Boolean(canManageBilling)
        };
    };

    const createPortalSession = async (orgId, returnUrl) => {
        const billing = await db.getBillingStatusByOrgId(orgId);
        if (!billing?.stripe_customer_id) {
            const err = new Error("Stripe customer not found");
            err.statusCode = 400;
            throw err;
        }

        const safeReturnUrl = getSafeReturnUrl(returnUrl, appUrl);
        const session = await stripe.billingPortal.sessions.create({
            customer: billing.stripe_customer_id,
            return_url: safeReturnUrl
        });
        return session.url;
    };

    const createCheckoutSession = async (orgId, priceId) => {
        const plan = priceIdToPlan[priceId];
        if (!plan) {
            const err = new Error("Invalid priceId");
            err.statusCode = 400;
            throw err;
        }

        const session = await stripe.checkout.sessions.create({
            mode: "subscription",
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: `${appUrl}/billing/success`,
            cancel_url: `${appUrl}/billing/cancel`,
            client_reference_id: String(orgId),
            metadata: { org_id: String(orgId) }
        });

        return session.url;
    };

    const handleWebhook = async (rawBody, signature, webhookSecret) => {
        if (!webhookSecret) {
            throw new Error("Missing STRIPE_WEBHOOK_SECRET");
        }

        const event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);

        const alreadyProcessed = await db.isStripeEventProcessed(event.id);
        if (alreadyProcessed) {
            return { received: true, ignored: true };
        }

        switch (event.type) {
            case "checkout.session.completed":
                await handleCheckoutCompleted(event.data.object);
                break;
            case "customer.subscription.updated":
            case "customer.subscription.deleted":
                await handleSubscriptionUpdate(event.data.object);
                break;
            default:
                break;
        }

        await db.markStripeEventProcessed(event.id);
        return { received: true };
    };

    const handleCheckoutCompleted = async (session) => {
        const orgId = Number(session?.metadata?.org_id || session?.client_reference_id);
        if (!Number.isFinite(orgId) || orgId <= 0) {
            return;
        }

        const billingUpdate = {
            stripe_customer_id: session.customer || null,
            stripe_subscription_id: session.subscription || null
        };

        if (session.subscription) {
            const subscription = await stripe.subscriptions.retrieve(session.subscription);
            const priceId = subscription.items?.data?.[0]?.price?.id;
            billingUpdate.plan = priceIdToPlan[priceId] || null;
            billingUpdate.subscription_status = subscription.status || null;
            billingUpdate.current_period_end = subscription.current_period_end
                ? new Date(subscription.current_period_end * 1000)
                : null;
        }

        await db.upsertBillingForOrg(orgId, billingUpdate);
    };

    const handleSubscriptionUpdate = async (subscription) => {
        const customerId = subscription.customer;
        if (!customerId) return;

        const orgId = await db.getOrgIdByCustomerId(customerId);
        if (!orgId) return;

        const priceId = subscription.items?.data?.[0]?.price?.id;
        const billingUpdate = {
            stripe_customer_id: customerId,
            stripe_subscription_id: subscription.id || null,
            plan: priceIdToPlan[priceId] || null,
            subscription_status: subscription.status || null,
            current_period_end: subscription.current_period_end
                ? new Date(subscription.current_period_end * 1000)
                : null
        };

        await db.upsertBillingForOrg(orgId, billingUpdate);
    };

    return {
        getBillingStatus,
        createPortalSession,
        createCheckoutSession,
        handleWebhook
    };
};

const getSafeReturnUrl = (returnUrl, appUrl) => {
    if (returnUrl && appUrl && returnUrl.startsWith(appUrl)) {
        return returnUrl;
    }
    if (appUrl) return appUrl;
    return "http://localhost:3000";
};

module.exports = { createStripeService };
