# Commission Tracker (Web App) — iPhone + PC

This is a lightweight web app that mirrors your Excel payplan logic:
- Unit commission based on "Discount > $200?"
- Add-ons (PermaPlate/Nitro/Pulse/Finance/Warranty/T&W)
- Trade hold commission = floor(Hold/1000) * 100
- Total deal commission = Unit + Add-ons + Trade hold

## Quick start (local)
1) Install Python 3.11+.
2) In Terminal / PowerShell:
   ```bash
   cd commission_tracker_app
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Mac:
   source .venv/bin/activate

   pip install -r requirements.txt
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
3) Open:
- On your PC: http://localhost:8000
- On your iPhone (same Wi‑Fi): http://<YOUR_PC_IP>:8000

Tip: find your PC IP with:
- Windows: `ipconfig`
- Mac: `ifconfig` (look for inet)

## Make it available anywhere (recommended)
Deploy to a service like Render/Fly.io/Railway, or run on a small home server.
This app uses SQLite by default (simple + reliable).

## Importing your existing Excel
This v1 is built to match your payplan rules. If you want, you can import
your existing Excel deals into the DB with a small script (ask and I’ll add it).


## Supabase (Transaction Pooler)
In Supabase, go to **Project Settings → Database → Connection Pooling** and copy the **Transaction** pooler connection string (port **6543**).
Paste that string into Render as the `DATABASE_URL` environment variable.

