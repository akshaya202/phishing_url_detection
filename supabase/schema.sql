-- Supabase Schema for Dynamic Phishing URL Detection System
-- This file contains all table definitions, indexes, and RLS policies

-- ============================================================================
-- TABLES
-- ============================================================================

-- Profiles table (extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- URL Scans table
CREATE TABLE IF NOT EXISTS url_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  domain TEXT,
  prediction TEXT NOT NULL CHECK (prediction IN ('safe', 'suspicious', 'phishing')),
  confidence REAL NOT NULL DEFAULT 0,
  risk_score REAL NOT NULL DEFAULT 0,
  severity TEXT CHECK (severity IN ('low', 'medium', 'high')),
  is_phishing BOOLEAN DEFAULT FALSE,
  detection_reasons JSONB,
  extracted_features JSONB,
  ssl_status JSONB,
  domain_info JSONB,
  reputation_info JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Threat Intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES url_scans(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  threat_type TEXT,
  reputation TEXT,
  details JSONB,
  checked_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES url_scans(id) ON DELETE CASCADE,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'read')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- API Logs table (for admin access only)
CREATE TABLE IF NOT EXISTS api_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  ip_address INET,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Model Versions table
CREATE TABLE IF NOT EXISTS model_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version TEXT UNIQUE NOT NULL,
  accuracy REAL,
  precision REAL,
  recall REAL,
  f1 REAL,
  confusion_matrix JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX idx_profiles_email ON profiles(email);
CREATE INDEX idx_profiles_role ON profiles(role);
CREATE INDEX idx_url_scans_user_id ON url_scans(user_id);
CREATE INDEX idx_url_scans_created_at ON url_scans(created_at DESC);
CREATE INDEX idx_url_scans_prediction ON url_scans(prediction);
CREATE INDEX idx_threat_intelligence_scan_id ON threat_intelligence(scan_id);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_api_logs_user_id ON api_logs(user_id);
CREATE INDEX idx_api_logs_created_at ON api_logs(created_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_versions ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- PROFILES RLS Policies
-- ============================================================================

-- Users can view their own profile
CREATE POLICY "Users can view their own profile"
  ON profiles FOR SELECT
  USING (auth.uid() = id);

-- Users can update their own profile
CREATE POLICY "Users can update their own profile"
  ON profiles FOR UPDATE
  USING (auth.uid() = id);

-- Admins can view all profiles
CREATE POLICY "Admins can view all profiles"
  ON profiles FOR SELECT
  USING (
    auth.uid() IN (
      SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
    )
  );

-- ============================================================================
-- URL_SCANS RLS Policies
-- ============================================================================

-- Users can view their own scans
CREATE POLICY "Users can view their own scans"
  ON url_scans FOR SELECT
  USING (auth.uid() = user_id);

-- Users can create scans
CREATE POLICY "Users can create their own scans"
  ON url_scans FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can update their own scans
CREATE POLICY "Users can update their own scans"
  ON url_scans FOR UPDATE
  USING (auth.uid() = user_id);

-- Admins can view all scans
CREATE POLICY "Admins can view all scans"
  ON url_scans FOR SELECT
  USING (
    auth.uid() IN (
      SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
    )
  );

-- ============================================================================
-- THREAT_INTELLIGENCE RLS Policies
-- ============================================================================

-- Users can view threats related to their scans
CREATE POLICY "Users can view threats from their scans"
  ON threat_intelligence FOR SELECT
  USING (
    scan_id IN (
      SELECT id FROM url_scans WHERE user_id = auth.uid()
    )
  );

-- Admins can view all threats
CREATE POLICY "Admins can view all threats"
  ON threat_intelligence FOR SELECT
  USING (
    auth.uid() IN (
      SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
    )
  );

-- ============================================================================
-- ALERTS RLS Policies
-- ============================================================================

-- Users can view their own alerts
CREATE POLICY "Users can view their own alerts"
  ON alerts FOR SELECT
  USING (auth.uid() = user_id);

-- Users can update their own alerts
CREATE POLICY "Users can update their own alerts"
  ON alerts FOR UPDATE
  USING (auth.uid() = user_id);

-- Admins can view all alerts
CREATE POLICY "Admins can view all alerts"
  ON alerts FOR SELECT
  USING (
    auth.uid() IN (
      SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
    )
  );

-- ============================================================================
-- API_LOGS RLS Policies
-- ============================================================================

-- Only admins can view API logs
CREATE POLICY "Admins can view all API logs"
  ON api_logs FOR SELECT
  USING (
    auth.uid() IN (
      SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
    )
  );

-- Only backend service can insert API logs (via service role key)
CREATE POLICY "Backend can insert API logs"
  ON api_logs FOR INSERT
  WITH CHECK (true); -- This should only be called from backend with service role key

-- ============================================================================
-- MODEL_VERSIONS RLS Policies
-- ============================================================================

-- Everyone can view model versions
CREATE POLICY "Everyone can view model versions"
  ON model_versions FOR SELECT
  USING (true);

-- Only admins can insert model versions
CREATE POLICY "Admins can insert model versions"
  ON model_versions FOR INSERT
  WITH CHECK (
    auth.uid() IN (
      SELECT id FROM profiles WHERE role = 'admin' AND auth.uid() = id
    )
  );

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function to handle profile creation on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, role)
  VALUES (new.id, new.email, new.raw_user_meta_data ->> 'full_name', 'user');
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create profile on user signup
CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- Function to update profile updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_profile_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to update profile timestamp
CREATE OR REPLACE TRIGGER on_profile_updated
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.update_profile_updated_at();

-- Function to update url_scans updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_scan_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to update scan timestamp
CREATE OR REPLACE TRIGGER on_scan_updated
  BEFORE UPDATE ON public.url_scans
  FOR EACH ROW
  EXECUTE FUNCTION public.update_scan_updated_at();

-- Function to update alerts updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_alert_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to update alert timestamp
CREATE OR REPLACE TRIGGER on_alert_updated
  BEFORE UPDATE ON public.alerts
  FOR EACH ROW
  EXECUTE FUNCTION public.update_alert_updated_at();

-- ============================================================================
-- INITIAL DATA (if needed)
-- ============================================================================

-- Note: Admin user should be created manually via Supabase UI
-- or after initial deployment via:
-- INSERT INTO profiles (id, email, full_name, role) VALUES (...);
