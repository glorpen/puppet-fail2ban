define fail2ban::jail(
  $enabled = true,
  $port = '0:65535',
  $protocol = 'tcp',
  $log_path = undef,
  $max_retry = 5,
  $ban_time = 600,
  $ban_action = 'iptables-multiport',
  $find_time = 600,
  $action = undef,
  $filter = $name,
  $chain = 'INPUT',
  
  $backend = 'auto',
  $use_dns = 'warn',
  $log_encoding = 'auto',
  $ignore_ip = '127.0.0.1/8',
  
  $conf = {},
  
  $content = undef,
  $source = undef
){
  include fail2ban
  
  if ! $::fail2ban::manage_jails {
    fail('Managing jails was disabled')
  }

  validate_integer($max_retry)
  validate_integer($ban_time)
  validate_integer($find_time)
  #TODO validation

  if $::fail2ban::manage_filters {
    Fail2ban::Filter[$filter]
    ->Fail2ban::Jail[$name]
  }
  
  $jail_conf = "${::fail2ban::jail_d_dir}/${name}.conf"
  
  if ! $content and ! $source {
    $norm_port = $port ? {
      undef => undef,
      default => join(flatten([$port]), ',')
    }
  
	  $config = merge($conf, {
	    'enabled' => $enabled? {
	      true => 'true',
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
	    'ignoreip' => $ignore_ip
	  })
	  
	  file { $jail_conf:
	    owner => 'root',
	    content => epp('fail2ban/sections.epp',{
	      'sections' => {$name => $config}
	    })
	  }
  } else {
    file { $jail_conf:
      owner => 'root',
      content => $content,
      source => $source
    }
  }
  
  if $::fail2ban::manage_firewall {
	  firewallchain { "f2b-${title}:filter:IPv4":
	    ensure => $::fail2ban::ensure,
	    purge  => false
	  }
  }
}