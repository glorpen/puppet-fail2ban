class fail2ban(
  $ensure = present,
  $package_ensure = true,
  $manage_firewall = $::fail2ban::manage_firewall,
  $loglevel = 'ERROR',
  $logtarget = 'STDERR',
  $syslogsocket = 'auto',
  $socket = $::fail2ban::socket,
  $pidfile = $::fail2ban::pidfile,
  $dbfile = $::fail2ban::dbfile,
  $dbpurgeage = 86400,
  
  $jail_d_dir     = $::fail2ban::jail_d_dir,
  $filter_d_dir   = $::fail2ban::filter_d_dir,
  $action_d_dir   = $::fail2ban::action_d_dir,
  $conf_d_dir     = $::fail2ban::conf_d_dir,
  $conf_file      = $::fail2ban::conf_file,
  $jail_conf_file = $::fail2ban::jail_conf_file
){

  if not ( $loglevel in ['CRITICAL','ERROR','WARNING','NOTICE','INFO','DEBUG'] ){
    fail("Unsupported loglevel value ${loglevel}")
  }
  
  if not ( $logtarget in ['STDOUT', 'STDERR', 'SYSLOG'] ){
    validate_absolute_path($loglevel, "Unsupported log value ${loglevel}")
  }
  
  if not ( $dbfile in ['None', ':memory:'] ){
    validate_absolute_path($dbfile, "Unsupported database path ${dbfile}")
  }
  
  if $syslogsocket != 'auto' {
    validate_absolute_path($syslogsocket, "Unsupported syslogsocket value ${$syslogsocket}")
  }
  
  validate_absolute_path($socket)
  validate_absolute_path($pidfile)

  if $package_ensure != undef {
    package { 'fail2ban':
      ensure => $package_ensure
    }~>File[$conf_file]
  }
  
  file { $conf_file:
    ensure => $ensure,
    mode => 'u=rw,go=r',
    content => epp('modules/fail2ban/fail2ban.conf.epp', {
      'loglevel' => $loglevel,
      'logtarget' => $logtarget,
      'syslogsocket' => $syslogsocket,
      'socket' => $socket,
      'pidfile' => $pidfile,
      'dbfile' => $dbfile,
      'dbpurgeage' => $dbpurgeage,
    })
  }
  
  file { $jail_d_dir:
    ensure => 'directory',
    recurse => true,
    force => true,
    ensure => $ensure
  }
  
  file { $conf_d_dir:
    ensure => 'directory',
    recurse => true,
    force => true,
    ensure => $ensure
  }
  
  file { $action_d_dir:
    ensure => 'directory',
    recurse => true,
    force => true,
    ensure => $ensure
  }
  
  file { $filter_d_dir:
    ensure => 'directory',
    recurse => true,
    force => true,
    ensure => $ensure
  }

}
