class fail2ban::jail::sshd(
  $ban_time = 3600,
  $find_time = 1200,
  $log_path = $::fail2ban::common_paths::syslog_authpriv,
  $conf = {}
) inherits fail2ban::common_paths {
  fail2ban::jail{'sshd':
    port    => 'ssh',
    ban_time => $ban_time,
    find_time => $find_time,
    log_path => $log_path,
    conf    => $conf
  }
}
