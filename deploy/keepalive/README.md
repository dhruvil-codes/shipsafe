# InstaBox keepalive Worker

This small Cloudflare Worker makes a scheduled, harmless request to one existing InstaBox machine. It reads machine state, resumes a suspended machine or starts a stopped machine using the documented InstaBox API, then executes `true` with a five second command timeout. Creating and deleting machines are outside this Worker.

## Configure

Set `INSTABOX_API_KEY` and `INSTABOX_SANDBOX_ID` as encrypted Worker secrets with `wrangler secret put`. The API key needs machine read, write, and exec scopes. Keep both values out of `wrangler.jsonc`, source control, logs, and public routes.

## Run locally and deploy

Use Wrangler's local mode to inspect the `/health` response. That route only returns `ok`; it never invokes InstaBox. Deployment is a separate operator action and is not part of preparing these files.

The cron expression runs every 20 minutes. Cron delivery is not an uptime guarantee, and this Worker does not change the machine's `autoSuspendAfterSeconds` setting (which remains 1800 seconds). It does not install a cron job inside the VM. Confirm the machine's idle-reset behavior with a controlled observation before relying on periodic activity. A request could be delayed, fail, or miss the idle window. The machine's running time may incur charges under the account's current billing limits; this Worker does not estimate or cap those charges.

Failures throw from the scheduled handler and log only a fixed status code. API responses, credentials, and command output are not logged. Unexpected machine states fail visibly without a lifecycle action.
