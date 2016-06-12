define fail2ban::filter::ignorecommand(
  $source  = undef,
  $content = undef
){
  include fail2ban
  
  if ! $::fail2ban::manage_filters {
    fail('Managing filters was disabled')
  }
  
  file { "${::fail2ban::filter_ignorecmd_d}/${title}":
    content => $content,
    source => $source,
    mode => 'a=rx,u+w'
  }
}
