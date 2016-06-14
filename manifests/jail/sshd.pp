class fail2ban::jail::sshd(
  $bantime = 3600,
  $logpath = $::fail2ban::common_paths::syslog_authpriv,
  $conf = {}
) inherits fail2ban::common_paths {
  fail2ban::jail{'sshd':
    port    => 'ssh',
    bantime => $bantime,
    logpath => $logpath,
    conf    => $conf
  }
}
