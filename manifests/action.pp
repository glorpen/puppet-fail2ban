define fail2ban::action(
  $content = undef,
  $source = undef
){

  include fail2ban;
  
  if ! $::fail2ban::manage_actions {
    fail('Managing actions was disabled')
  }

  $conf_name = ($title =~ /\.[a-z]+$/) ? {
    true => $title,
    default => "${title}.conf"
  }
  
  file { "${::fail2ban::action_d_dir}/${conf_name}":
    source => $source,
    content => $content,
    notify => [Service[$::fail2ban::service_name]]
  }
}
