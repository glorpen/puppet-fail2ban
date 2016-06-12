function fail2ban::validate_options(
  String $log_level,
  String $log_target,
  String $syslog_socket,
  String $socket,
  String $pid_file,
  String $db_file,
  Integer $db_purge_age
){
    if not ( $log_level in ['CRITICAL','ERROR','WARNING','NOTICE','INFO','DEBUG'] ){
      fail("Unsupported loglevel value ${log_level}")
    }
    
    if not ( $log_target in ['STDOUT', 'STDERR', 'SYSLOG'] ){
      validate_absolute_path($log_target, "Unsupported log_target value ${log_target}")
    }
    
    if not ( $db_file in ['None', ':memory:'] ){
      validate_absolute_path($db_file, "Unsupported database path ${db_file}")
    }
    
    if $syslog_socket != 'auto' {
      validate_absolute_path($syslog_socket, "Unsupported syslogsocket value ${$syslog_socket}")
    }
    
    validate_absolute_path($socket)
    validate_absolute_path($pid_file)
}
