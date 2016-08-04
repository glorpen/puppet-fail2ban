define fail2ban::filter(
  $failregex = undef,
  $ignoreregex = undef,
  
  $content = undef,
  $source  = undef,
){
  include fail2ban
  $filter_conf = "${::fail2ban::filter_d_dir}/${title}.conf"
  
  if ! $::fail2ban::manage_filters {
    fail('Managing filters was disabled')
  }
  
  if ! $content and ! $source {
    $config = delete_undef_values(merge({
      # default values
    }, $conf))
    
    file { $filter_conf:
      owner => 'root',
      filter => $filter,
      content => epp('fail2ban/sections.epp',{
        'sections' => {'Definition' =>  $config}
      }),
      notify => [Service[$::fail2ban::service_name]]
    }
  } else {
	  file { $filter_conf:
	    owner => 'root',
	    content => $content,
	    source => $source,
	    notify => [Service[$::fail2ban::service_name]]
	  }
  }

}
