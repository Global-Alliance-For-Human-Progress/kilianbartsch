# kilianbartsch.com

Password-gated host for personal HTML dashboards. Put `.html` files (and assets) in `private/`; the home page lists them automatically after login.

Plain Node.js, no dependencies, so there is no `npm install` step and no `requirements.txt`.

## Run locally

```
SITE_PASSWORD=test node server.js
```

## Deploy on Render

Create a **Web Service** from this repo and use these settings in the form:

| Field | Value |
| --- | --- |
| Language | **Node** (not Python 3; change the autofilled dropdown if it says Python) |
| Branch | `main` |
| Region | Frankfurt (EU Central) |
| Root Directory | leave empty |
| Build Command | `yarn install` (Render's Node default, works fine) or `true`; nothing to build, `npm install` also works |
| Start Command | `node server.js` (or `npm start`) |
| Instance type | Free is fine (it spins down when idle, first request after that is slow) |
| Health Check Path (under Advanced) | `/healthz` |

Node 18 or newer is required (set in `package.json`). Render's default Node version is fine. Do not set `PORT`, Render provides it.

### Environment variables

Add these under **Environment Variables** (or paste into "Add from .env"):

```
SITE_PASSWORD=choose-a-long-password
COOKIE_SECRET=any-long-random-string
```

- `SITE_PASSWORD` (required): the password for the login page.
- `COOKIE_SECRET` (recommended): signs the session cookie. Use the "Generate" button in Render. If unset it falls back to `SITE_PASSWORD`.

### Blueprint alternative

[render.yaml](render.yaml) already contains all of the above. Instead of filling in the form, choose **New > Blueprint**, pick this repo, and enter `SITE_PASSWORD` when prompted (`COOKIE_SECRET` is auto-generated).

### Custom domain

In the service's **Settings > Custom Domains**, add `kilianbartsch.com` and follow Render's DNS instructions.
