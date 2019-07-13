define fail2ban::jail(
  Enum['present', 'absent', 'disabled'] $ensure = 'present',
  Variant[String, Integer, Array[Variant[String, Integer]], Undef] $port = undef,
  Optional[String] $protocol = undef,
  Optional[String] $log_path = undef,
  Optional[Integer] $max_retry = undef,
  Optional[Integer] $ban_time = undef,
  Optional[Integer] $find_time = undef,
  Array[Variant[String, Tuple[String, Hash[String, String]]]] $action = [],
  String $filter = $name,
  Optional[String] $chain = undef,
  
  Optional[String] $backend = undef,
  Optional[String] $use_dns = undef,
  Optional[String] $log_encoding = undef,
  Optional[Array[Variant[Stdlib::IP::Address::V4::CIDR, Stdlib::IP::Address::V6::CIDR]]] $ignore_ip = undef,

  $ignore_command = undef,
  String $ignore_command_args = '',
  
  Hash[String, Fail2ban::Multiline] $config = {},
  
  $content = undef,
  $source = undef
){
  include fail2ban
  
  $ensure_file = $ensure ? {
    'absent' => 'absent',
    default  => 'present'
  }

  if (defined(Fail2ban::Filter[$filter])) {
    Fail2ban::Filter[$filter]
    ->Fail2ban::Jail[$name]
  }

  if ($ignore_command and defined(Fail2ban::Ignorecommand[$ignore_command])) {
    Fail2ban::Ignorecommand[$ignore_command]
    ->Fail2ban::Jail[$name]
  }
  
  $jail_conf = "${::fail2ban::jail_d_path}/${name}.conf"
  
  if ! $content and ! $source {
    $norm_port = $port ? {
      undef => undef,
      default => join(flatten([$port]), ',')
    }
    $norm_filter = $filter == $name ? {
      true => undef,
      default => $filter
    }
    $norm_ignore_ip = $ignore_ip ? {
      undef => undef,
      default => join(flatten($ignore_ip), " ")
    }
    $norm_ignore_command = $ignore_command?{
      undef => undef,
      default => "%(ignorecommands_dir)s/${ignore_command} ${ignore_command_args}"
    }
    $norm_action = $action.map | $i | {
      if $i =~ String {
        $i
      } else {
        $opts = join($i[1].map | $k, $v | {
          "${k}=\"${v}\""
        }, ', ')
        "${i[0]}[${opts}]"
      }
    }
  
	  $_config = delete_undef_values(merge({
	    'enabled' => $ensure? {
	      'present' => 'true',
	      default => 'false'
	    },
	    'logpath' => $log_path,
	    'maxretry' => $max_retry,
	    'findtime' => $find_time,
      'bantime' => $ban_time,
	    'action' => $norm_action,
	    'filter' => $norm_filter,
	    'backend' => $backend,
	    'usedns' => $use_dns,
	    'logencoding' => $log_encoding,
	    'ignoreip' => $norm_ignore_ip,
      'port' => $norm_port,
      'protocol' => $protocol,
      'chain' => $chain,
      'ignorecommand' => $norm_ignore_command
	  }, $config))
	  
	  file { $jail_conf:
      ensure  => $ensure_file,
	    owner   => 'root',
	    content => epp('fail2ban/sections.epp',{
	      'sections' => {$name => $_config}
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
