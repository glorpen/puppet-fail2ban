function fail2ban::validate_options(
  String $log_level,
  String $log_target,
  String $syslog_socket,
  String $socket,
  String $pid_file,
  String $db_file,
  Integer $db_purge_age
){
    if ! ( $log_level in ['CRITICAL','ERROR','WARNING','NOTICE','INFO','DEBUG'] ){
      fail("Unsupported loglevel value ${log_level}")
    }
    
    if ! ( $log_target in ['STDOUT', 'STDERR', 'SYSLOG'] ) and ! is_absolute_path($log_target) {
      fail("Unsupported log_target value ${log_target}")
    }
    
    if ! ( $db_file in ['None', ':memory:'] ) and ! is_absolute_path($db_file) {
      fail("Unsupported database path ${db_file}")
    }
    
    if $syslog_socket != 'auto' and ! is_absolute_path($syslog_socket) {
      fail("Unsupported syslogsocket value ${$syslog_socket}")
    }
    
    validate_absolute_path($socket)
    validate_absolute_path($pid_file)
}
