# aerascps. on Cloudflare

The whole site as one Cloudflare Worker: public pages, scenepack studio and
control room, both locked behind Discord sign-in. Free to run, no card needed.

- `worker.js`: the site's server code
- `public/index.html`: the pages
- `wrangler.jsonc`: the settings Cloudflare reads when it deploys

## Setup

1. **Create the D1 database.** Cloudflare dashboard, Storage & Databases, D1,
   Create. Name it `aerascps`. Copy its **Database ID**.
2. **The ID is already in `wrangler.jsonc`.** Check the Discord IDs and `BASE_URL`
   under `vars` while you are there. The database's name in the file is `aerascps`;
   only the ID has to match.
3. **Deploy.** Put this folder in a GitHub repository, then in the dashboard go to
   Workers & Pages, Create, import that repository and deploy. (Or, with Node.js
   installed, run `npx wrangler deploy` inside this folder.)
4. **Add the Discord secret.** Open the Worker, Settings, Variables and Secrets,
   Add. Type: **Secret**. Name: `DISCORD_CLIENT_SECRET`. Value: your Discord
   client secret. Save and deploy.
5. **Connect your domain.** Worker, Settings, Domains & Routes, add
   `aerascp.xyz` as a custom domain. The domain has to be managed by Cloudflare,
   and removed from Vercel.
6. **Discord redirect.** In the Discord Developer Portal, OAuth2, Redirects, keep
   `https://aerascp.xyz/auth/callback`.

The database table is created by the site itself the first time it runs.

## Adding scenepacks

Staff access, scenepack studio: pick a category, type the name, paste a link to
the scenepack (Google Drive, Mega and so on), submit. Then approve it in the
control room.

## Optional: file uploads (R2)

Without R2 the studio asks for a link. To let creators upload the file itself:

1. Dashboard, Storage & Databases, R2. Cloudflare asks for a payment method
   before the first bucket. 10 GB of storage a month is free; more is billed.
2. Create a bucket named `aerascps-files`.
3. In `wrangler.jsonc` switch on the `r2_buckets` block (instructions are in the
   file) and deploy again.

Files are sent in 50 MB parts, so big scenepacks get past Cloudflare's 100 MB
request limit. `MAX_UPLOAD_MB` sets the largest file allowed.

## Other settings (optional, add under `vars`)

- `ADMIN_USER_IDS`: Discord user IDs that are always admin, comma separated
- `REQUEST_WEBHOOK`: a Discord webhook URL; every request is posted there.
  Add this one as a Secret in the dashboard instead, since anyone holding the
  URL can post to your channel.

## Good to know

- Roles are checked at sign-in. A role change applies the next time that person
  signs in. Sessions last 12 hours.
- Resetting the Discord client secret signs everyone out once.
- Free plan limits: 100,000 requests a day for the Worker.
