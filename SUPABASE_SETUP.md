# Supabase Integration Guide

## Overview
This project has been successfully integrated with **Supabase** as the primary PostgreSQL database and authentication system. This guide explains how to set up, configure, and use the system.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supabase Setup](#supabase-setup)
3. [Database Migration](#database-migration)
4. [Environment Variables](#environment-variables)
5. [Backend Setup](#backend-setup)
6. [Frontend Setup](#frontend-setup)
7. [API Endpoints](#api-endpoints)
8. [Row-Level Security (RLS)](#row-level-security-rls)
9. [Running the Project](#running-the-project)
10. [Testing](#testing)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Node.js 16+ (for frontend)
- Python 3.8+ (for backend)
- Supabase account (free tier at https://supabase.com)
- Git
- A terminal/command-line interface

---

## Supabase Setup

### Step 1: Create a Supabase Project

1. Go to [supabase.com](https://supabase.com) and sign up/login
2. Click "New Project"
3. Fill in the project details:
   - **Project Name**: `phishing-detection`
   - **Database Password**: Create a strong password
   - **Region**: Choose the closest region to your location
4. Click "Create new project" and wait for it to complete (5-10 minutes)

### Step 2: Get Your Credentials

1. Go to **Settings → API** in your Supabase dashboard
2. Copy and save these values:
   - **Project URL**: This is your `SUPABASE_URL`
   - **Anon Public Key**: This is your `SUPABASE_ANON_KEY`
   - **Service Role Key**: This is your `SUPABASE_SERVICE_ROLE_KEY` (keep this secret!)

⚠️ **Important**: The Service Role Key should ONLY be used on the backend server. Never expose it in frontend code or to the browser.

---

## Database Migration

### Step 1: Create Tables and Functions

1. In Supabase, go to **SQL Editor** (or **SQL** in the sidebar)
2. Click **"New Query"**
3. Copy the entire contents of `supabase/schema.sql` from this project
4. Paste it into the SQL editor
5. Click **"Run"**

This will create:
- `profiles` table
- `url_scans` table
- `threat_intelligence` table
- `alerts` table
- `api_logs` table
- `model_versions` table
- All necessary indexes and RLS policies
- Triggers for automatic timestamp updates

### Step 2: Create an Admin User

1. Go to **Authentication → Users** in Supabase dashboard
2. Click **"Add user"** → **"Add user manually"**
3. Enter:
   - **Email**: `admin@college.edu`
   - **Password**: Create a strong password
4. Click **"Create user"**
5. Go to **SQL Editor** and run:

```sql
UPDATE profiles
SET role = 'admin'
WHERE email = 'admin@college.edu';
```

---

## Environment Variables

### Backend (.env)

Create a `.env` file in the project root directory with:

```bash
# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key-here
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here

# JWT/Security
SECRET_KEY=your-super-secret-key-change-this
ALGORITHM=HS256

# Server
API_HOST=localhost
API_PORT=8000
```

Replace the placeholder values with your actual Supabase credentials.

### Frontend (.env)

Create a `.env` file in the `frontend/` directory with:

```bash
VITE_API_URL=http://localhost:8000
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key-here
```

⚠️ **Never commit `.env` files to Git!** They're already in `.gitignore`.

---

## Backend Setup

### Step 1: Install Python Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Step 2: Run Backend Server

```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend will start at `http://localhost:8000`

---

## Frontend Setup

### Step 1: Install Dependencies

```bash
cd frontend
npm install
```

### Step 2: Run Development Server

```bash
npm run dev
```

The frontend will start at `http://localhost:5173`

---

## API Endpoints

### Authentication (Legacy - works with both SQLite and Supabase)

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### URL Scanning

- `POST /api/scan` - Scan a URL (returns prediction, confidence, risk, reason)
- `GET /api/scan/{scan_id}` - Get detailed scan information
- `GET /api/scans` - Get user's scans (paginated)
- `GET /api/scans/history` - Get user's scan history

### Threat Intelligence

- `GET /api/threats` - Get threat intelligence data
- `POST /api/reports` - Submit URL report (legacy)

### Alerts

- `GET /api/alerts` - Get user's alerts
- `PATCH /api/alerts/{alert_id}` - Mark alert as read

### Analytics

- `GET /api/analytics` - Get analytics and statistics

### Admin Endpoints (Protected - require admin role)

- `GET /api/admin/summary` - Get system summary
- `GET /api/admin/metrics` - Get ML model metrics
- `GET /api/admin/users` - Get all users
- `GET /api/admin/scans` - Get all scans
- `GET /api/admin/threats` - Get all threat intelligence
- `GET /api/admin/alerts` - Get all alerts
- `GET /api/admin/logs` - Get API logs
- `GET /api/admin/reports` - Get user reports (legacy)
- `POST /api/admin/reports/{report_id}/decision` - Review report
- `POST /api/admin/retrain` - Retrain ML model

All API endpoints return JSON responses with appropriate HTTP status codes.

---

## Row-Level Security (RLS)

The database uses RLS to ensure users can only access their own data:

### Profiles Table
- Users can view and update their own profile
- Admins can view all profiles

### URL Scans Table
- Users can view and create their own scans
- Admins can view all scans

### Alerts Table
- Users can view and update their own alerts
- Admins can view all alerts

### API Logs Table
- Only admins can view logs

### Threat Intelligence & Model Versions
- Users can view threats from their scans
- Admins can view all data

RLS policies are **automatically applied** when data is accessed through the Supabase client. The backend uses the service role key for admin operations.

---

## Running the Project Locally

### Step 1: Start the Backend

```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 2: Start the Frontend (in a new terminal)

```bash
cd frontend
npm run dev
```

### Step 3: Access the Application

Open your browser and go to: `http://localhost:5173`

You should see:
- The PhishSense dashboard
- Login/Register forms on the right
- Demo admin login button

### Test Accounts

**Demo Admin:**
- Email: `admin@college.edu`
- Password: (use the password you set in Supabase)

**Create New Account:**
- Use the Register form in the application

---

## Testing

### Test User Registration & Login

1. Click "Register" tab
2. Fill in name, email, and password
3. Click "Create account"
4. You should be logged in and see your profile
5. Click "Logout" to test logout
6. Use "Login" tab to sign back in

### Test URL Scanning

1. Enter a URL like `https://www.google.com` in the scan input
2. Click "Scan URL"
3. See the prediction, confidence, risk score, and explanation
4. Scan results are saved to `url_scans` table in Supabase

### Test Admin Dashboard

1. Use the Demo Admin button or login with admin credentials
2. Navigate to Admin page (top right menu)
3. You should see:
   - Model metrics (accuracy, precision, recall, F1)
   - Verified reports section
   - Confusion matrix
   - Retraining button

### Test Alerts

1. Login as regular user
2. Scan a phishing URL (e.g., `http://fake-paypal.xyz`)
3. If risk is high, an alert is created in the `alerts` table
4. Go to `/api/alerts` endpoint to verify

### Verify Supabase Data

1. Go to Supabase dashboard → **Table Editor**
2. Check these tables for data:
   - `profiles` - should have your user
   - `url_scans` - should have your scan results
   - `alerts` - should have alerts from high-risk scans
   - `api_logs` - should have API call logs

---

## Troubleshooting

### Issue: "Invalid API key" or Authentication Error

**Solution:**
- Verify `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` are correct
- Check that they're in the `.env` file with no typos or extra spaces
- Restart the backend server after changing `.env`

### Issue: "RLS policy violation"

**Solution:**
- This usually means the RLS policy is preventing access
- Verify the user is authenticated (has valid JWT token)
- Check that the `profiles` table has an entry for the user
- The auto-trigger should create a profile on user signup; verify it ran

### Issue: "Relation does not exist" or "Table not found"

**Solution:**
- The schema migration didn't run completely
- Go back to **SQL Editor** in Supabase
- Run the `supabase/schema.sql` script again
- Check for any error messages

### Issue: Frontend can't connect to backend

**Solution:**
- Verify backend is running: `http://localhost:8000/` should return `{"message": "..."}`
- Check `VITE_API_URL` in `frontend/.env`
- Verify CORS is enabled in backend (it should be by default)
- Check browser console for error messages

### Issue: Model not loading or training fails

**Solution:**
- Ensure the `datasets/phishing_dataset.csv` exists
- Check that the `models/` directory exists and is writable
- Verify the ML model files (`model_v1.joblib`, etc.) are in place
- Check backend logs for detailed error messages

---

## Security Notes

1. **Never commit `.env` files** to Git - they're in `.gitignore`
2. **Service Role Key** should ONLY be used on the backend - never expose to frontend
3. **RLS is enabled** on all tables - users cannot access other users' data through RLS
4. **JWT tokens** should be stored securely (HttpOnly cookies are recommended for production)
5. **Validate and sanitize** all user input on both frontend and backend
6. **Use HTTPS** in production (Supabase requires it)

---

## Production Deployment

When deploying to production:

1. **Update VITE_API_URL** to your production backend URL
2. **Update VITE_SUPABASE_URL** to use your Supabase project URL
3. **Store secrets** in your deployment platform's secret manager (not in code)
4. **Enable HTTPS** for all endpoints
5. **Use environment-specific configurations** for dev, staging, and production
6. **Set up proper CORS** restrictions for your domain
7. **Enable database backups** in Supabase
8. **Monitor API usage** in Supabase dashboard
9. **Scale appropriately** based on traffic

---

## Support & Resources

- **Supabase Docs**: https://supabase.com/docs
- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **React Docs**: https://react.dev/
- **Project Issues**: Check the README.md for troubleshooting

---

**Last Updated**: 2026-08-30
**Project**: Dynamic Phishing URL Detection System with Supabase
