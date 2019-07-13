define fail2ban::filter(
  Enum['present', 'absent'] $ensure = 'present',
  Array[String] $before = [],
  Array[String] $after = [],
  Optional[Fail2ban::Multiline] $failregex = undef,
  Optional[Fail2ban::Multiline] $ignoreregex = undef,
  Hash[String, Fail2ban::Multiline] $config = {},
  
  String $content = undef,
  String $source  = undef,
){
  include fail2ban
  $filter_conf = "${::fail2ban::filter_d_path}/${title}.conf"
  
  if $ensure == 'present' {
    if ! $content and ! $source {
      file { $filter_conf:
        owner   => 'root',
        filter  => $filter,
        content => epp('fail2ban/sections.epp',{
          'sections'     => {
            'INCLUDES' => {
              'before' => join($before, ' '),
              'after'  => join($after, ' '),
            },
            'Definition' => merge($config, delete_undef_values({
              'failregex'   => $failregex,
              'ignoreregex' => $ignoreregex
            }))
          }
        }),
        notify  => [Service[$::fail2ban::service_name]]
      }
    } else {
      file { $filter_conf:
        owner => 'root',
        content => $content,
        source => $source,
        notify => [Service[$::fail2ban::service_name]]
      }
    }
  } else {
    file { $filter_conf:
      ensure => absent
    }
  }
}
