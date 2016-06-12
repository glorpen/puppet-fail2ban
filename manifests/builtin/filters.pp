class fail2ban::builtin::filters(
){
  fail2ban::filter{'3proxy': source => 'puppet:///modules/fail2ban/filter.d/3proxy.conf'}
}
