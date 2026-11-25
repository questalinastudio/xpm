-- Workers remove their own heartbeat row on graceful shutdown, so a restart
-- does not leave a permanently "stale" worker on the dashboard.
GRANT DELETE ON worker_heartbeats TO xpm_worker;
