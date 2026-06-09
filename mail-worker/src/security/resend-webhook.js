import { Webhook } from 'svix';

export const resendWebhookSecret = (env) => {
	return String(env?.resend_webhook_secret || '').trim();
};

export const verifyResendWebhookPayload = (secret, payload, headers) => {
	if (!secret) {
		return { ok: false, code: 503, error: 'webhook secret is not configured' };
	}

	try {
		const webhook = new Webhook(secret);
		return { ok: true, body: webhook.verify(payload, headers) };
	} catch {
		return { ok: false, code: 401, error: 'invalid webhook signature' };
	}
};
