define fail2ban::conf(
  $log_level = undef,
  $log_target = undef,
  $syslog_socket = undef,
  $socket = undef,
  $pid_file = undef,
  $db_file = undef,
  $db_purge_age = undef,
  $custom = {}
){

  include fail2ban
  
  if ! $::fail2ban::manage_conf {
    fail('Managing config was disabled')
  }
  
  $conf_file = "${::fail2ban::conf_d_dir}/${title}.conf"

  file { $conf_file:
    mode => 'u=rw,go=r',
    content => epp('modules/fail2ban/entry.epp',{
      'title' => 'Definition',
      'config' => merge(delete_undef_values({
        'loglevel' => $log_level,
	      'logtarget' => $log_target,
	      'syslogsocket' => $syslog_socket,
	      'socket' => $socket,
	      'pidfile' => $pid_file,
	      'dbfile' => $db_file,
	      'dbpurgeage' => $db_purge_age,
      }), $custom)
    })
  }
}
