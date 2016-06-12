class fail2ban::builtin::ignorecommands {
  fail2ban::filter::ignorecommand{'apache-fakegooglebot':
    source => 'puppet:///modules/fail2ban/filter.d/ignorecommands/apache-fakegooglebot'
  }
}
