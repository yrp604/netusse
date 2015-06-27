Netusse is kernel network stack fuzzer for unix systems. It was initially written during my Google Summer of Code in 2006. It has been able to find the following kind of bugs.

  * [memory disclosure](http://www.openbsd.org/cgi-bin/cvsweb/src/sys/netinet/ip_output.c.diff?r1=1.200;r2=1.201)
  * [double](http://svnweb.freebsd.org/base?view=revision&revision=230104) [something](http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html)
  * [NULL dereference](http://marc.info/?l=openbsd-cvs&m=125880991716458&w=2)
  * [memory exhaustion](http://www.freebsd.org/cgi/query-pr.cgi?pr=100219)
  * integer overflow (link soon)
  * heap overflow (link soon)
