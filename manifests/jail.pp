define fail2ban::jail(
  Enum['present', 'absent', 'disabled'] $ensure = 'present',
  $port = '0:65535',
  $protocol = 'tcp',
  $log_path = undef,
  Integer $max_retry = 5,
  Integer $ban_time = 600,
  $ban_action = 'iptables-multiport',
  Integer $find_time = 600,
  $action = undef,
  $filter = $name,
  $chain = 'INPUT',
  
  $backend = 'auto',
  $use_dns = 'warn',
  $log_encoding = 'auto',
  $ignore_ip = '127.0.0.1/8',

  $ignore_command = undef,
  String $ignore_command_args = '',
  
  $conf = {},
  
  $content = undef,
  $source = undef
){
  include fail2ban
  
  $ensure_file = $ensure ? {
    'absent' => 'absent',
    default => 'present'
  }

  if (defined(Fail2ban::Filter[$filter])) {
    Fail2ban::Filter[$filter]
    ->Fail2ban::Jail[$name]
  }

  if ($ignore_command && defined(Fail2ban::Ignorecommand[$ignore_command])) {
    Fail2ban::Ignorecommand[$ignore_command]
    ->Fail2ban::Jail[$name]
  }
  
  $jail_conf = "${::fail2ban::jail_d_dir}/${name}.conf"
  
  if ! $content and ! $source {
    $norm_port = $port ? {
      undef => undef,
      default => join(flatten([$port]), ',')
    }
  
	  $config = merge($conf, {
	    'enabled' => $ensure? {
	      'present' => 'true',
	      default => 'false'
	    },
	    'logpath' => $log_path,
	    'maxretry' => $max_retry,
	    'findtime' => $find_time,
	    'action' => $action? {
	      undef => "${ban_action}[name=${name}, bantime=\"${ban_time}\", port=\"${norm_port}\", protocol=\"${protocol}\", chain=\"${chain}\"]",
        default => $action
	    },
	    'filter' => $filter,
	    'backend' => $backend,
	    'usedns' => $use_dns,
	    'logencoding' => $log_encoding,
	    'ignoreip' => $ignore_ip,
      'ignorecommand' => $ignore_command?{
        undef => undef,
        default => "${ignore_command} ${ignore_command_args}"
      }
	  })
	  
	  file { $jail_conf:
      ensure => $ensure_file
	    owner => 'root',
	    content => epp('fail2ban/sections.epp',{
	      'sections' => {$name => $config}
	    }),
      notify => [Service[$::fail2ban::service_name]]
	  }
  } else {
    file { $jail_conf:
      ensure => $ensure_file,
      owner => 'root',
      content => $content,
      source => $source,
      notify => [Service[$::fail2ban::service_name]]
    }
  }
  
  # $ban_action ~= ^iptables-
  if $::fail2ban::manage_firewall {
	  firewallchain { "f2b-${title}:filter:IPv4":
	    ensure => $::fail2ban::ensure,
	    purge  => false
	  }
  }
}
