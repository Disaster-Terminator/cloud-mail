import resendService from '../service/resend-service';
import app from '../hono/hono';
import { resendWebhookSecret, verifyResendWebhookPayload } from '../security/resend-webhook';

app.post('/webhooks',async (c) => {
	const payload = await c.req.text();
	const verification = verifyResendWebhookPayload(resendWebhookSecret(c.env), payload, {
		'svix-id': c.req.header('svix-id') || '',
		'svix-timestamp': c.req.header('svix-timestamp') || '',
		'svix-signature': c.req.header('svix-signature') || '',
	});

	if (!verification.ok) {
		return c.text(verification.error, verification.code);
	}

	await resendService.webhooks(c, verification.body);
	return c.text('success', 200)
})
