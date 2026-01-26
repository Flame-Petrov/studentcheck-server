const express = require("express");

const createBillingRouter = (stripeService) => {
    const router = express.Router();

    router.get("/status", requireAuth, async (req, res) => {
        try {
            const { orgId, role } = req.auth;
            const canManageBilling = isOrgAdmin(role);
            const status = await stripeService.getBillingStatus(orgId, canManageBilling);
            return res.status(200).send(status);
        } catch (error) {
            console.error("❌ Billing status error:", error);
            return res.status(500).send({ error: "Internal server error" });
        }
    });

    router.post("/portal", requireAuth, requireOrgAdmin, async (req, res) => {
        try {
            const { orgId } = req.auth;
            const returnUrl = req.body?.returnUrl;
            const url = await stripeService.createPortalSession(orgId, returnUrl);
            return res.status(200).send({ url });
        } catch (error) {
            console.error("❌ Billing portal error:", error);
            const status = error.statusCode || 500;
            return res.status(status).send({ error: error.message || "Internal server error" });
        }
    });

    return router;
};

const createBillingWebhookHandler = (stripeService) => {
    return async (req, res) => {
        const signature = req.headers["stripe-signature"];
        if (!signature) {
            return res.status(400).send({ error: "Missing Stripe signature" });
        }
        try {
            const result = await stripeService.handleWebhook(
                req.body,
                signature,
                process.env.STRIPE_WEBHOOK_SECRET
            );
            return res.status(200).send(result);
        } catch (error) {
            console.error("❌ Stripe webhook error:", error);
            return res.status(400).send({ error: "Webhook signature verification failed" });
        }
    };
};

const requireAuth = (req, res, next) => {
    const orgId = Number(req.headers["x-org-id"]);
    const role = String(req.headers["x-user-role"] || "").toLowerCase();

    if (!Number.isFinite(orgId) || orgId <= 0) {
        return res.status(401).send({ error: "Unauthorized" });
    }

    req.auth = { orgId, role };
    return next();
};

const requireOrgAdmin = (req, res, next) => {
    if (!isOrgAdmin(req.auth?.role)) {
        return res.status(403).send({ error: "Forbidden" });
    }
    return next();
};

const isOrgAdmin = (role) => {
    return role === "owner" || role === "admin";
};

module.exports = {
    createBillingRouter,
    createBillingWebhookHandler
};
