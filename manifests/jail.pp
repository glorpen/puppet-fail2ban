define fail2ban::jail(
  $filter = $name,
  $enabled = true,
  $port = undef,
  $logpath = undef,
  $maxretry = undef,
  $bantime = undef,
  $banaction = undef,
  $findtime = undef,
  $action = undef,
  $conf = {},
  
  $content = undef,
  $source = undef
){
  include fail2ban
  
  if ! $::fail2ban::manage_jails {
    fail('Managing jails was disabled')
  }

  if $maxretry != undef {
    validate_integer($maxretry)
  }
  
  if $bantime != undef {
    validate_integer($bantime)
  }
  
  if $findtime != undef {
    validate_integer($findtime)
  }

  if $::fail2ban::manage_filters {
    Fail2ban::Filter[$filter]
    ->Fail2ban::Jail[$name]
  }
  
  $jail_conf = "${::fail2ban::jail_d_dir}/${name}.conf"
  
  if ! $content and ! $source {
  
	  $config = delete_undef_values(merge({
	    'enabled' => $enabled? {
	      true => 'true',
	      default => 'false'
	    },
	    'port' => $port ? {
	      undef => undef,
	      default => join(flatten([$port]), ',')
	    },
	    'logpath' => $logpath,
	    'maxretry' => $maxretry,
	    'bantime' => $bantime,
	    'banaction' => $banaction,
	    'findtime' => $findtime,
	    'action' => $action,
	    'filter' => $filter
	  }, $conf))
	  
	  file { $jail_conf:
	    owner => 'root',
	    content => epp('fail2ban/sections.epp',{
	      'sections' => {'Definition' =>  $config}
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