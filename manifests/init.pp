# = Class: fail2ban
#
# Manages fail2ban service.
#
# == Parameters:
#
# [*ensure*]
#   Ensure parameter passed onto child resources.
#   Default: present
#
class fail2ban(
  $ensure = present,
  $package_ensure = present,
  $manage_firewall = $::fail2ban::params::manage_firewall,
  $manage_actions = true,
  $manage_filters = true,
  $manage_jails = true,
  $manage_conf = true,
  
  $log_level = 'ERROR',
  $log_target = 'STDERR',
  $syslog_socket = $::fail2ban::params::syslog_socket,
  $socket = $::fail2ban::params::socket,
  $pid_file = $::fail2ban::params::pid_file,
  $db_file = $::fail2ban::params::db_file,
  $db_purge_age = 86400,
  $use_main_conf = true,
  
  $jail_d_dir     = $::fail2ban::params::jail_d_dir,
  $filter_d_dir   = $::fail2ban::params::filter_d_dir,
  $action_d_dir   = $::fail2ban::params::action_d_dir,
  $conf_d_dir     = $::fail2ban::params::conf_d_dir,
  $conf_file      = $::fail2ban::params::conf_file,
  $jail_conf_file = $::fail2ban::params::jail_conf_file
){
  if $package_ensure != undef {
    package { 'fail2ban':
      ensure => $ensure ? {
        present => $package_ensure,
        default => absent
      }
    }~>File[$conf_file]
  }
  
  if $manage_conf {
  
    if $use_main_conf {
  
	    fail2ban::validate_options(
	     $log_level,
	     $log_target,
	     $syslog_socket,
	     $socket,
	     $pid_file,
	     $db_file,
	     $db_purge_age
	    )
	  
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
