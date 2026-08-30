
# Dynamic Phishing URL Detection System with Supabase

This project implements a full-stack phishing URL detection system with:

- React + Tailwind frontend
- FastAPI backend
- **Supabase PostgreSQL database** with local SQLite fallback
- **Row-Level Security (RLS)** for data isolation
- Random Forest-based phishing detection with retraining flow
- User auth, scan history, suspicious URL reporting, and admin verification
- **Real-time alerts** for high-risk URLs
- **Admin dashboard** with system-wide analytics
- **Audit logging** for security and compliance

## Structure

- `frontend/` – Vite React app with dashboard and scanner UI
- `backend/` – FastAPI API service with Supabase integration
- `ml/` – feature extraction and training logic
- `datasets/` – dataset inspection and phishing URL CSV
- `models/` – saved model and metrics artifacts
- `supabase/` – database schema and migration files

## 🚀 Quick Start

### Option 1: With Supabase (Recommended)

1. **Create Supabase account** at https://supabase.com
2. **Follow setup guide**:
   ```bash
   cat SUPABASE_SETUP.md
   ```
3. **Complete remaining steps below**

### Option 2: Without Supabase (Local SQLite)

Skip Supabase setup and proceed to step 1 below (no credentials needed).

### Setup Steps

1. Create a Python virtual environment and install backend dependencies:
   ```bash
   cd backend
   python -m venv .venv
   . .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```

3. **Configure environment** (if using Supabase):
   ```bash
   cp .env.example .env
   # Edit .env with your Supabase credentials
   ```

4. Start the backend:
   ```bash
   cd backend
   python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

5. Start the frontend:
   ```bash
   cd frontend
   npm run dev
   ```

6. Open browser at `http://localhost:5173` and use credentials:
   - **Email**: `admin@college.edu`
   - **Password**: `admin123` (or your Supabase password)

## 📚 Documentation

- **[SUPABASE_SETUP.md](SUPABASE_SETUP.md)** – Complete Supabase setup guide
- **[SUPABASE_RLS.md](SUPABASE_RLS.md)** – Row-Level Security details
- **[SUPABASE_INTEGRATION.md](SUPABASE_INTEGRATION.md)** – Integration summary

## Notes

- Reported URLs are never visited or executed.
- Only verified reports are used for retraining.
- Admin routes are protected and require an admin token.
