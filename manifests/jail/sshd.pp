class fail2ban::jail::sshd(
  Integer $ban_time = 3600,
  Integer $find_time = 1200,
  Optional[String] $log_path = undef,
  Hash $config = {}
) {
  fail2ban::jail{'sshd':
    port      => 'ssh',
    ban_time  => $ban_time,
    find_time => $find_time,
    log_path  => $log_path,
    action    => [
      [
        'iptables-multiport',
        {
          'name'     => '%(__name__)s',
          'bantime'  => '%(bantime)s',
          'port'     => '%(port)s',
          'protocol' => '%(protocol)s',
          'chain'    => '%(chain)s'
        }
      ],
    ],
    *        => $config
  }
}
