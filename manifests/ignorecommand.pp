define fail2ban::ignorecommand(
  $source  = undef,
  $content = undef
){
  include fail2ban
  
  file { "${::fail2ban::filter_ignorecmd_d}/${title}":
    content => $content,
    source => $source,
    mode => 'a=rx,u+w'
  }
}
