-- Add HTTP health check path to backends
ALTER TABLE backends ADD COLUMN health_check_path TEXT DEFAULT NULL;
