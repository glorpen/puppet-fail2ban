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

  if $maxretry != undef {
    validate_integer($maxretry)
  }
  
  if $bantime != undef {
    validate_integer($bantime)
  }
  
  if $findtime != undef {
    validate_integer($findtime)
  }

  include fail2ban
  contain(Fail2ban::Filter[$filter])
  
  $jail_conf = "${::fail2ban::jail_d_dir}/${name}.conf"
  
  if ! $content and ! $source {
  
	  $config = merge({
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
	  }, $conf)
	  
	  file { $jail_conf:
	    owner => 'root',
	    filter => $filter,
	    content => epp('modules/fail2ban/entry.epp',{
	      'title' => $title,
	      'config' => $config
	    })
	  }
  } else {
    file { $jail_conf:
      owner => 'root',
      filter => $filter,
      content => $content,
      source => $source
    }
  }
}