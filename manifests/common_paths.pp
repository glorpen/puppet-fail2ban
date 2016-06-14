class fail2ban::common_paths{
  if $::osfamily in ['Gentoo','Debian'] {
    $syslog_authpriv = '/var/log/auth.log'
  } elsif $::osfamily == 'RedHat' {
    $syslog_authpriv = '/var/log/secure'
  } elsif $::osfamily == 'FreeBSD' {
    $syslog_authpriv = '/var/log/auth.log'
  }
  
  #TODO OSX
  
}