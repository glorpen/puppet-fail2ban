# function can be disabled
# function can be replaced
class fail2ban(
  $ensure = present,
  $package_ensure = true,
  $manage_firewall = $::fail2ban::manage_firewall,
  $manage_actions = true,
  $manage_filters = true,
  $manage_jails = true,
  $manage_conf = true,
  
  $log_level = 'ERROR',
  $log_target = 'STDERR',
  $syslog_socket = $::fail2ban::params::syslog_socket,
  $socket = $::fail2ban::socket,
  $pid_file = $::fail2ban::pid_file,
  $db_file = $::fail2ban::db_file,
  $db_purge_age = 86400,
  
  $jail_d_dir     = $::fail2ban::jail_d_dir,
  $filter_d_dir   = $::fail2ban::filter_d_dir,
  $action_d_dir   = $::fail2ban::action_d_dir,
  $conf_d_dir     = $::fail2ban::conf_d_dir,
  $conf_file      = $::fail2ban::conf_file,
  $jail_conf_file = $::fail2ban::jail_conf_file
){

  if not ( $log_level in ['CRITICAL','ERROR','WARNING','NOTICE','INFO','DEBUG'] ){
    fail("Unsupported loglevel value ${loglevel}")
  }
  
  if not ( $log_target in ['STDOUT', 'STDERR', 'SYSLOG'] ){
    validate_absolute_path($log_target, "Unsupported log value ${loglevel}")
  }
  
  if not ( $dbfile in ['None', ':memory:'] ){
    validate_absolute_path($dbfile, "Unsupported database path ${dbfile}")
  }
  
  if $syslog_socket != 'auto' {
    validate_absolute_path($syslog_socket, "Unsupported syslogsocket value ${$syslog_socket}")
  }
  
  validate_absolute_path($socket)
  validate_absolute_path($pidfile)

  if $package_ensure != undef {
    package { 'fail2ban':
      ensure => $package_ensure
    }~>File[$conf_file]
  }
  
  if $manage_conf {
	  file { $conf_file:
	    ensure => $ensure,
	    mode => 'u=rw,go=r',
	    content => epp('modules/fail2ban/fail2ban.conf.epp', {
	      'loglevel' => $log_level,
	      'logtarget' => $log_target,
	      'syslogsocket' => $syslog_socket,
	      'socket' => $socket,
	      'pidfile' => $pid_file,
	      'dbfile' => $db_file,
	      'dbpurgeage' => $db_purge_age,
	    })
	  }
	  
    file { $conf_d_dir:
	    ensure => 'directory',
	    recurse => true,
	    force => true,
	    ensure => $ensure
	  }
  }
  
  if $manage_jails {
	  file { $jail_d_dir:
	    ensure => 'directory',
	    recurse => true,
	    force => true,
	    ensure => $ensure
	  }
  }
  
  if $manage_actions {
	  file { $action_d_dir:
	    ensure => 'directory',
	    recurse => true,
	    force => true,
	    ensure => $ensure
	  }
  }
  
  if $manage_filters {
	  file { $filter_d_dir:
	    ensure => 'directory',
	    recurse => true,
	    force => true,
	    ensure => $ensure
	  }
  }

}
