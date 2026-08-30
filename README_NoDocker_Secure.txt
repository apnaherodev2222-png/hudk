NO-DOCKER HARDENED HOSTING BOT

1) Create a dedicated non-root Linux user for this bot. Do NOT run it as root.
2) Put .env next to the Python file and set BOT_TOKEN, OWNER_ID, ADMIN_ID.
3) Install dependencies:
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
4) Start:
   python3 'HOSTING BOT_NoDocker_Secure.py'

Important:
- This is NOT a true sandbox. Uploaded code still runs on the same OS account.
- Resource limits, timeouts, path checks, and secret stripping reduce risk.
- Automatic pip/npm installation is OFF by default. Keep ALLOW_AUTO_INSTALL=0 on a public host.
- The previously exposed Telegram bot token must be revoked and replaced.
