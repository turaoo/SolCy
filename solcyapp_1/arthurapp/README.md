# SolCy — Web App

A self-hosted malware analysis SaaS platform.

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set environment variables
```bash
cp .env.example .env
# Edit .env with your keys
```

### 3. Copy the analysis engine
Make sure `solcy.py` is in the parent folder of `solcyapp/`

### 4. Run locally
```bash
python app.py
```
Visit http://localhost:5000

---

## Deploy to Railway (recommended — free tier available)

1. Go to railway.app and create a free account
2. Click "New Project" → "Deploy from GitHub"
3. Push this folder to a GitHub repo and connect it
4. In Railway dashboard → Variables, add all keys from .env.example
5. Railway auto-detects the Procfile and deploys

---

## Deploy to Render (alternative free option)

1. Go to render.com → New Web Service
2. Connect your GitHub repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add environment variables in the Render dashboard

---

## Stripe Setup

1. Go to dashboard.stripe.com
2. Create two products:
   - "SolCy Pro" — $19/month recurring
   - "SolCy Team" — $49/month recurring
3. Copy the Price IDs (start with `price_`) into your .env
4. Set up a webhook pointing to: https://yourdomain.com/stripe-webhook
   - Listen for: checkout.session.completed, customer.subscription.deleted
5. Copy the webhook signing secret into STRIPE_WEBHOOK_SECRET

---

## Subscription Plans

| Plan | Price | Scans | Features |
|------|-------|-------|----------|
| Free | $0 | 5/month | HTML report, basic analysis |
| Pro | $19/mo | Unlimited | + VirusTotal, MalwareBazaar, PDF reports, CSV |
| Team | $49/mo | Unlimited | + 5 seats, API access, priority support |

---

## File Structure

```
solcyapp/
  app.py              # Flask backend
  requirements.txt    # Python dependencies
  Procfile            # For Railway/Render deployment
  templates/
    index.html        # Landing page
    login.html        # Sign in
    register.html     # Create account
    dashboard.html    # User dashboard + scan upload
    pricing.html      # Pricing page with Stripe checkout
    scan_detail.html  # Individual scan results
solcy.py    # Analysis engine (must be in parent folder)
```
