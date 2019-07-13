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
  Variant[Enum['present', 'absent'], String] $ensure = 'present',
  String $package_name = 'fail2ban',
  Boolean $manage_firewall = true,
  Enum['CRITICAL','ERROR','WARNING','NOTICE','INFO','DEBUG'] $log_level = 'ERROR',
  Variant[Enum['STDOUT', 'STDERR', 'SYSLOG'], Stdlib::Absolutepath] $log_target = 'STDERR',
  Variant[Enum['auto'], Stdlib::Absolutepath, Undef] $syslog_socket = undef,
  Optional[Stdlib::Absolutepath] $socket = undef,
  Optional[Stdlib::Absolutepath] $pid_file = undef,
  Variant[Enum['None', ':memory:'], Stdlib::Absolutepath, Undef] $db_file = undef,
  String $service_name = 'fail2ban',
  Variant[String, Integer] $db_purge_age = 86400,
	Stdlib::Absolutepath $config_path = '/etc/fail2ban',
	String $jail_d_dir = 'jail.d',
	String $action_d_dir = 'action.d',
	String $filter_d_dir = 'filter.d',
	Hash[String, Fail2ban::Multiline] $jail_defaults = {}
) {

	$jail_d_path = "${config_path}/${jail_d_dir}"
	$action_d_path = "${config_path}/${action_d_dir}"
	$filter_d_path = "${config_path}/${filter_d_dir}"
	$filter_ignorecmd_d = "${filter_d_path}/ignorecommands"

  $ensure_dir = $ensure ? {
    absent => 'absent',
    default => 'directory'
  }
	$ensure_file = $ensure ? {
    'absent' => 'absent',
    default => 'present'
  }


	if $::facts['os']['family'] == 'RedHat' and $ensure != 'absent' {
		ensure_packages(['epel-release'], {'ensure' => 'present'})
		Package['epel-release']
		->Package[$package_name]
	}

  package { $package_name:
    ensure => $ensure
  }->
  service { $service_name:
    ensure => running,
    enable => true
  }

	file { "${config_path}/fail2ban.local":
		ensure => $ensure_file,
		mode => 'u=rw,go=r',
		content => epp('fail2ban/sections.epp', {
			sections => {
				'Definition' => delete_undef_values({
					'loglevel' => $log_level,
					'logtarget' => $log_target,
					'syslogsocket' => $syslog_socket,
					'socket' => $socket,
					'pidfile' => $pid_file,
					'dbfile' => $db_file,
					'dbpurgeage' => $db_purge_age,
				})
			}
		}),
		subscribe => Package[$package_name]
	}

	file { "${config_path}/jail.local":
		ensure => $ensure_file,
		mode => 'u=rw,go=r',
		content => epp('fail2ban/sections.epp', {
			'sections' => {
				'DEFAULT' => delete_undef_values($jail_defaults)
			}
		}),
		subscribe => Package[$package_name]
	}
  
	file { $jail_d_path:
		ensure => $ensure_dir,
		recurse => true,
		force => true,
		purge => true
	}
  
  if $manage_firewall {
		g_firewall::protect { 'f2b ipv4 rules':
			regex => [' -j f2b-'],
			chain => 'INPUT:filter:IPv4'
		}
		
		g_firewall::protect { 'f2b ipv6 rules':
			regex => [' -j f2b-'],
			chain => 'INPUT:filter:IPv6'
		}
  }
}
