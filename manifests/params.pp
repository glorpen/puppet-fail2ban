class fail2ban::params{
  $conf_dir        = '/etc/fail2ban'
  $jail_d_dir      = '/etc/fail2ban/jail.d'
  $filter_d_dir    = '/etc/fail2ban/filter.d'
  $action_d_dir    = '/etc/fail2ban/action.d'
  $conf_d_dir      = '/etc/fail2ban/fail2ban.d'
  $socket          = '/run/fail2ban/fail2ban.sock'
  $syslog_socket   = 'auto'
  $pid_file        = '/run/fail2ban/fail2ban.pid'
  $db_file         = '/var/lib/fail2ban/fail2ban.sqlite3'
  $manage_firewall = defined('firewall')
  $conf_file       = '/etc/fail2ban/fail2ban.conf'
  $jail_conf_file  = '/etc/fail2ban/jail.conf'
  $package_name    = 'fail2ban'
}
