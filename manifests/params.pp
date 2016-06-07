define fail2ban::params{
  $jail_d_dir      = '/etc/fail2ban/jail.d'
  $filter_d_dir    = '/etc/fail2ban/filter.d'
  $action_d_dir    = '/etc/fail2ban/filter.d'
  $conf_d_dir      = '/etc/fail2ban/fail2ban.d'
  $socket          = '/run/fail2ban/fail2ban.sock'
  $pidfile         = '/run/fail2ban/fail2ban.pid'
  $dbfile          = '/var/lib/fail2ban/fail2ban.sqlite3'
  $manage_firewall = defined('firewall')
  $conf_file       = '/etc/fail2ban/fail2ban.conf'
  $jail_conf_file  = '/etc/fail2ban/jail.conf'
}
