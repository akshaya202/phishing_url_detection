
# Dynamic Phishing URL Detection System with Supabase

This project implements a full-stack phishing URL detection system with:

- React + Tailwind frontend
- FastAPI backend
- **Supabase PostgreSQL database** with local SQLite fallback
- **Row-Level Security (RLS)** for data isolation
- Multi-dataset phishing detection with model comparison and retraining flow
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

## Multi-dataset ML pipeline

Place URL CSV files in `datasets/`. On startup, and whenever an administrator uses
the retrain action, every CSV is inspected and normalized to:

```text
url      verdict
...      0 or 1
```

`0` means legitimate/safe and `1` means phishing/malicious. The loader detects
common URL and label column names. For unusual files, add an entry to
`DATASET_CONFIG` in `ml/dataset_pipeline.py`, including an explicit
`label_mapping`. Unknown numeric encodings are rejected and reported rather than
being guessed. Missing URLs/labels and duplicate URLs are removed before splitting.

Each dataset report includes its usable record count and class distribution. The
saved `models/latest_model.json` also contains the final combined count,
distribution, per-model metrics, selected model, feature names, and optional
external-test metrics.

When at least four compatible URL datasets are present, the first three sorted by
filename are used for training and the fourth is held out as an unseen external
test dataset. With fewer than four compatible datasets, all compatible datasets
are used for training. The current `PhishingData.csv` is intentionally reported
as incompatible because it has engineered features but no URL column.

The trainer compares Random Forest, Logistic Regression, and SVM. XGBoost is
included automatically when installed:

```bash
pip install xgboost
```

The same feature extractor is used during training and real-time `/api/scan`
prediction. The selected model is saved as a versioned Joblib file, so existing
frontend and backend prediction behavior remains unchanged.

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
