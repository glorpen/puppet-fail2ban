define fail2ban::action(
  Enum['present', 'absent'] $ensure = 'present',
  Array[String] $before = [],
  Array[String] $after = [],
  Fail2ban::Multiline $action_start = '',
  Fail2ban::Multiline $action_stop = '',
  Fail2ban::Multiline $action_check = '',
  Fail2ban::Multiline $action_ban = '',
  Fail2ban::Multiline $action_unban = '',
  Hash[String, Fail2ban::Multiline] $init = {},
  Hash[String, Hash[String, Fail2ban::Multiline]] $conditional_inits = {}, # "family=inet6" => "Init?family=inet6"
  
  String $content = undef,
  String $source  = undef,
){
  include fail2ban;
  
  $action_conf = "${::fail2ban::action_d_path}/${title}.conf"
  
  if $ensure == 'present' {
    if ! $content and ! $source {

      $_inits = Hash($conditional_inits.map | $k, $v | {
        ["Init?${k}", $v]
      })

      file { $action_conf:
        owner   => 'root',
        filter  => $filter,
        content => epp('fail2ban/sections.epp',{
          'sections' => {
            'INCLUDES'   => {
              'before' => join($before, ' '),
              'after'  => join($after, ' '),
            }
            'Definition' => {
              'actionstart' => $action_start,
              'actionstop'  => $action_stop,
              'actioncheck' => $action_check,
              'actionban'   => $action_ban,
              'actionunban' => $action_unban,
            },
            'Init' => $init,
            *      => $_inits
          }
        }),
        notify  => [Service[$::fail2ban::service_name]]
      }
    } else {
      file { $action_conf:
        owner   => 'root',
        content => $content,
        source  => $source,
        notify  => Service[$::fail2ban::service_name]
      }
    }
  } else {
    file { $action_conf:
      ensure => absent
    }
  }
}
