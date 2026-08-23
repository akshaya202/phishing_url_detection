
# Dynamic Phishing URL Detection System with Crowdsourced Threat Intelligence

This project implements a full-stack phishing URL detection system with:

- React + Tailwind frontend
- FastAPI backend
- Supabase-ready data layer with local fallback
- Random Forest-based phishing detection with retraining flow
- User auth, scan history, suspicious URL reporting, and admin verification

## Structure

- `frontend/` – Vite React app with dashboard and scanner UI
- `backend/` – FastAPI API service
- `ml/` – feature extraction and training logic
- `datasets/` – dataset inspection and phishing URL CSV
- `models/` – saved model and metrics artifacts

## Quick start

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

3. Start the backend:
   ```bash
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

4. Start the frontend:
   ```bash
   cd frontend
   npm run dev -- --host 0.0.0.0
   ```

5. Open the frontend in a browser and use the demo admin credentials:
   - Email: `admin@college.edu`
   - Password: `admin123`

## Notes

- Reported URLs are never visited or executed.
- Only verified reports are used for retraining.
- Admin routes are protected and require an admin token.
