import { describe, expect, it } from 'vitest';
import { Webhook } from 'svix';
import { verifyResendWebhookPayload } from '../src/security/resend-webhook';

const secret = `whsec_${Buffer.from('test-secret').toString('base64')}`;

const signedHeaders = (payload) => {
	const webhook = new Webhook(secret);
	const timestamp = new Date();
	const id = 'msg_test';
	return {
		'svix-id': id,
		'svix-timestamp': `${Math.floor(timestamp.getTime() / 1000)}`,
		'svix-signature': webhook.sign(id, timestamp, payload),
	};
};

describe('resend webhook verification', () => {
	it('accepts a valid svix signature', () => {
		const payload = JSON.stringify({ type: 'email.delivered', data: { email_id: 'email_123' } });

		const result = verifyResendWebhookPayload(secret, payload, signedHeaders(payload));

		expect(result.ok).toBe(true);
		expect(result.body.type).toBe('email.delivered');
	});

	it('fails closed when the secret is missing', () => {
		const result = verifyResendWebhookPayload('', '{}', {});

		expect(result.ok).toBe(false);
		expect(result.code).toBe(503);
	});

	it('rejects a bad signature', () => {
		const result = verifyResendWebhookPayload(secret, '{}', {
			'svix-id': 'msg_test',
			'svix-timestamp': `${Math.floor(Date.now() / 1000)}`,
			'svix-signature': 'v1,bad',
		});

		expect(result.ok).toBe(false);
		expect(result.code).toBe(401);
	});
});
