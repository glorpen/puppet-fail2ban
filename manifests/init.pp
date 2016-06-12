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
  $package_name = $::fail2ban::params::package_name,
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
  
  $conf_dir       = $::fail2ban::params::conf_dir,
  $jail_d_dir     = $::fail2ban::params::jail_d_dir,
  $filter_d_dir   = $::fail2ban::params::filter_d_dir,
  $action_d_dir   = $::fail2ban::params::action_d_dir,
  $conf_d_dir     = $::fail2ban::params::conf_d_dir,
  $conf_file      = $::fail2ban::params::conf_file,
  $jail_conf_file = $::fail2ban::params::jail_conf_file,
  
  $add_builtin_filters = true,
  
) inherits fail2ban::params {

  $filter_ignorecmd_d = "${filter_d_dir}/ignorecommands"

  $ensure_dir = $ensure ? {
    present => 'directory',
    default => absent
  }

  package { $package_name:
    ensure => $ensure ? {
      present => $package_ensure,
      default => absent
    }
  }
  
  if $manage_conf {
    file { $conf_dir:
      ensure  => $ensure_dir,
      recurse => true,
      force   => true,
      purge   => true,
    }
  
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
		    content => epp('fail2ban/fail2ban.conf.epp', {
		      'loglevel' => $log_level,
		      'logtarget' => $log_target,
		      'syslogsocket' => $syslog_socket,
		      'socket' => $socket,
		      'pidfile' => $pid_file,
		      'dbfile' => $db_file,
		      'dbpurgeage' => $db_purge_age,
		    }),
		    subscribe => Package[$package_name]
		  }
	  }
	  
    file { $conf_d_dir:
	    ensure => $ensure_dir,
	    recurse => true,
	    force => true,
	    purge => true
	  }
  }
  
  if $manage_jails {
	  file { $jail_d_dir:
	    ensure => $ensure_dir,
	    recurse => true,
	    force => true,
	    purge => true
	  }
  }
  
  if $manage_actions {
	  file { $action_d_dir:
	    ensure => $ensure_dir,
	    recurse => true,
	    force => true,
	    purge => true
	  }
  }
  
  if $manage_filters {
	  file { $filter_d_dir:
	    ensure => $ensure_dir,
	    recurse => true,
	    force => true,
	    purge => true
	  }
	  
	  file { $filter_ignorecmd_d:
	    ensure => $::fail2ban::ensure_dir,
	    recurse => true,
	    force => true,
	    purge => true
	  }
	  
	  if $add_builtin_filters {
		  include fail2ban::builtin::filters
		  include fail2ban::builtin::ignorecommands
	  }
  }

}
