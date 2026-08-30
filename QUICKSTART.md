# Quick Start Guide - Supabase Integration

**Time to setup**: ~10 minutes  
**Difficulty**: Beginner-friendly

---

## 🎯 TL;DR

```bash
# 1. Setup Supabase project (https://supabase.com)
# 2. Copy project URL and API keys
# 3. Run this:

cp .env.example .env
# Edit .env with your Supabase credentials

# Backend
cd backend && pip install -r requirements.txt
python -m uvicorn main:app --reload

# Frontend (new terminal)
cd frontend && npm install
npm run dev

# Open http://localhost:5173
# Login: admin@college.edu / admin123
```

---

## Step-by-Step

### 1️⃣ Create Supabase Project (5 min)

Go to **https://supabase.com** → Sign up → Create project

Get these values:
- **Project URL**: e.g., `https://xxxx.supabase.co`
- **Anon Key**: Copy from Settings → API
- **Service Role Key**: Copy from Settings → API

### 2️⃣ Configure Environment (.env)

```bash
cp .env.example .env
```

Edit `.env`:
```
SUPABASE_URL=https://your-project-url.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
SECRET_KEY=any-secret-key
```

### 3️⃣ Create Database Schema (2 min)

In Supabase dashboard:
1. Go to **SQL Editor**
2. Click **New Query**
3. Copy entire contents of `supabase/schema.sql`
4. Paste into editor
5. Click **Run**

### 4️⃣ Start Backend (1 min)

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Should see: `INFO: Uvicorn running on http://0.0.0.0:8000`

### 5️⃣ Start Frontend (1 min)

```bash
cd frontend
npm install
npm run dev
```

Should see: `VITE Local: http://localhost:5173/`

### 6️⃣ Open & Test

1. Go to **http://localhost:5173**
2. Click "Demo Admin" button
3. Scan a URL like `https://google.com`
4. Go to Admin page to see dashboard

✅ **Done!**

---

## 🔧 What If It Doesn't Work?

### Backend won't start
```bash
# Check Python version
python --version  # Should be 3.8+

# Reinstall requirements
pip install --upgrade -r requirements.txt

# Check if port 8000 is free
# On Windows: netstat -ano | findstr :8000
# On Mac/Linux: lsof -i :8000
```

### Frontend won't start
```bash
# Clear npm cache
npm cache clean --force

# Reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node version
node --version  # Should be 16+
```

### Supabase connection error
```bash
# Check .env file exists and has correct URLs
cat .env

# Verify connection
curl https://your-project.supabase.co/rest/v1/
# Should return 401 (not found is also OK)
```

### RLS error "new row violates row-level security"
- Make sure you're logged in (token sent in header)
- User must exist in `profiles` table
- Run schema.sql migration again

---

## 📊 Verify It's Working

### Check Backend API
```bash
curl http://localhost:8000/
# Should return: {"message": "Dynamic Phishing URL Detection System API is running."}
```

### Check Frontend
Open http://localhost:5173/ and see:
- [ ] PhishSense header
- [ ] Scanner input box
- [ ] Login/Register forms
- [ ] Demo Admin button

### Check Supabase
1. Go to Supabase dashboard
2. Click **Table Editor**
3. Check these tables have data:
   - `profiles` ← your user
   - `url_scans` ← your scan results
   - `alerts` ← high-risk URL alerts

---

## 🎓 Common Tasks

### Create New User
1. Click "Register" tab
2. Enter name, email, password
3. Click "Create account"

### Scan URL
1. Login (or use Demo Admin)
2. Enter URL in scanner input
3. Click "Scan URL"
4. See results

### View Admin Dashboard
1. Use Demo Admin or login as admin
2. Click "Admin" in top menu
3. See metrics and reports

### Check Scan History
1. Login as user
2. Scroll down to "Live Analysis Feed"
3. See all your scans

---

## 🔐 Security Notes

⚠️ **IMPORTANT**:
- Never commit `.env` file
- Never share `SUPABASE_SERVICE_ROLE_KEY`
- Keep `SECRET_KEY` secret
- Only use `Service Role Key` on backend

---

## 📚 Need More Help?

- **Setup Guide**: Read `SUPABASE_SETUP.md`
- **API Reference**: Read `SUPABASE_INTEGRATION.md`
- **Security**: Read `SUPABASE_RLS.md`
- **Full Details**: Read `README.md`

---

## 🚀 Next Steps

1. Customize the app (colors, text, etc.)
2. Add more threat intelligence sources
3. Integrate with your security tools
4. Deploy to production
5. Add team members

---

**Questions?** Check the documentation files or the Supabase docs at https://supabase.com/docs
