**SSHFS Multiplexer** (SSHFS-MUX) was born because we live in the _cloud era_, where you are likely to have multiple/many machines and you want to share data among them.

## Originated from, but Beyond SSHFS ##
**SSHFS Multiplexer** (SSHFS-MUX) originates from [SSHFS](http://fuse.sourceforge.net/sshfs.html), but is more than SSHFS.

For example, by SSHFS, you can:

`$ sshfs host:/target/directory /local/mountpoint`

```
    directory          mountpoint
     /     \     ==>    /      \
  data1   data2      data1    data2
```

where via mountpoint, you can manipulate remote files as local ones.

By SSHFS-MUX, you also can:

`$ sshfsm host1:directory1 host2:directory2 /local/mountpoint`

```
    directory1     directory2         mountpoint
     /          +         \     ==>    /      \
  data1                  data2      data1    data2
```

where `directory1` and `directory2` are properly merged in to one
global namespace at `/local/mountpoint`.

This can be also achieved by using SSHFS and [UnionFS](http://www.fsl.cs.sunysb.edu/project-unionfs.html)/[UnionFS-FUSE](http://podgorny.cz/moin/UnionFsFuse). However, using SSHFS-MUX is more straightforward, easier, and efficient.

For more details, please refer to [Usage](Usage.md).

## Optimal Transfer Rate in Wide-Area Networks ##

Using SSH to transfer large data in long-fat network does not fully utilize the network capacity. This is because the transfer buffer is fixed in OpenSSH implementation, which is illustrated [here](http://www.psc.edu/networking/projects/hpn-ssh/) and can be solved by HPN-SSH.

If you feel tedious to patch OpenSSH and you trust your network, then you can try using _raw socket_ instead of SSH. Following chart shows how the optimal transfer rate is achieved by using raw TCP link.

![http://chart.apis.google.com/chart?chtt=Transfer+Rate+in+Long-Fat+Links&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|4K|8K|16K|32K|64K|128K|256K|512K|1M|2M|4M|8M|16M|1:|Block+Size|2:|0|10|20|3:|MB/sec&chxp=1,50|3,50&cht=lc&chd=t:93.21,48.04,52.39,40.17,59.37,100.00,62.50,74.40,55.40,76.26,63.21,56.42,46.12|28.79,7.93,3.71,2.04,7.16,0.00,2.94,1.47,1.85,1.53,1.15,1.27,1.79|97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37&chdl=SSHFSM+with+directport|SSHFS|Iperf&chco=ff6600,6699ff,333333&chls=1,1,0|1,1,0|1,3,3&nonsense=sshfs_in_wan.png](http://chart.apis.google.com/chart?chtt=Transfer+Rate+in+Long-Fat+Links&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|4K|8K|16K|32K|64K|128K|256K|512K|1M|2M|4M|8M|16M|1:|Block+Size|2:|0|10|20|3:|MB/sec&chxp=1,50|3,50&cht=lc&chd=t:93.21,48.04,52.39,40.17,59.37,100.00,62.50,74.40,55.40,76.26,63.21,56.42,46.12|28.79,7.93,3.71,2.04,7.16,0.00,2.94,1.47,1.85,1.53,1.15,1.27,1.79|97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37,97.37&chdl=SSHFSM+with+directport|SSHFS|Iperf&chco=ff6600,6699ff,333333&chls=1,1,0|1,1,0|1,3,3&nonsense=sshfs_in_wan.png)

_Point-to-point transfering 256MB data in different block sizes over the long-fat link_.

## Building Your Own Scalable, High-Performance Distributed File System On-the-Fly ##

Using SSHFS-MUX is more than that. You can even build a scalable and high-performance distributed file system on arbitrary machines in a few minutes. GMount has been proved practically useful by both micro-benchmark and real-world data-intensive applications in
multi-clusters environments.

Following chart shows that mounting a global file system takes less than 10 seconds on over 300 nodes across 12 sites.

![http://chart.apis.google.com/chart?chtt=GMount+File+System+Deploy+Time&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|69|158|194|207|236|266|272|282|293|304|314|329|1:|Nodes|2:|0|5|10|3:|Seconds&chxp=1,50|3,50&cht=lc&chd=t:27.58,29.10,29.22,36.97,34.56,72.62,95.95,77.57,88.14,97.50,98.71,100.00|0.00,14.82,10.42,24.78,22.41,41.28,23.92,30.84,43.66,41.02,44.30,44.51&chdl=Construction|Destruction&chco=ff6600,6699ff&chls=1,1,0|1,1,0&nonsense=gmnt_btime.png](http://chart.apis.google.com/chart?chtt=GMount+File+System+Deploy+Time&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|69|158|194|207|236|266|272|282|293|304|314|329|1:|Nodes|2:|0|5|10|3:|Seconds&chxp=1,50|3,50&cht=lc&chd=t:27.58,29.10,29.22,36.97,34.56,72.62,95.95,77.57,88.14,97.50,98.71,100.00|0.00,14.82,10.42,24.78,22.41,41.28,23.92,30.84,43.66,41.02,44.30,44.51&chdl=Construction|Destruction&chco=ff6600,6699ff&chls=1,1,0|1,1,0&nonsense=gmnt_btime.png)

Following charts shows that GMount has scalable metadata and I/O performance in WAN (up to 32 nodes across 4 sites).

![http://chart.apis.google.com/chart?chtt=GMount+Parallel+Meta+Performance&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|2|4|8|16|32|1:|Number+of+Concurrent+Clients|2:|0|35000|70000|3:|ops/sec&chxp=1,50|3,50&cht=lc&chd=t:5677.88,11462.57,20169.38,30273.13,39509.5|5554.08,12669.08,19448.81,23689.05,54430.85|6361.42,16617.19,26789.24,35022.21,61689.07|6259.38,12750.92,22211.4,32597.84,58331.15&chdl=mkdir|rmdir|stat|chmod&chds=0,70000&chco=ff6600,6699ff,000000,00ff00&chls=1,1,0|1,1,0&nonsense=gmnt_meta.png](http://chart.apis.google.com/chart?chtt=GMount+Parallel+Meta+Performance&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|2|4|8|16|32|1:|Number+of+Concurrent+Clients|2:|0|35000|70000|3:|ops/sec&chxp=1,50|3,50&cht=lc&chd=t:5677.88,11462.57,20169.38,30273.13,39509.5|5554.08,12669.08,19448.81,23689.05,54430.85|6361.42,16617.19,26789.24,35022.21,61689.07|6259.38,12750.92,22211.4,32597.84,58331.15&chdl=mkdir|rmdir|stat|chmod&chds=0,70000&chco=ff6600,6699ff,000000,00ff00&chls=1,1,0|1,1,0&nonsense=gmnt_meta.png)

![http://chart.apis.google.com/chart?chtt=GMount+Parallel+I/O+Performance&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|2|4|8|16|32|1:|Number+of+Concurrent+Clients|2:|0|4000|8000|3:|MB/sec&chxp=1,50|3,50&cht=lc&chd=t:155.31,338.56,530.63,985.66,1876.2|830.59,1595.1,3161.17,5943.67,7241.79&chdl=read|write&chds=0,8000&chco=ff6600,6699ff&chls=1,1,0|1,1,0&nonsense=gmnt_io.png](http://chart.apis.google.com/chart?chtt=GMount+Parallel+I/O+Performance&chts=000000,12&chs=500x200&chdlp=b&chf=bg,s,ffffff|c,s,ffffff&chxt=x,x,y,y&chxl=0:|2|4|8|16|32|1:|Number+of+Concurrent+Clients|2:|0|4000|8000|3:|MB/sec&chxp=1,50|3,50&cht=lc&chd=t:155.31,338.56,530.63,985.66,1876.2|830.59,1595.1,3161.17,5943.67,7241.79&chdl=read|write&chds=0,8000&chco=ff6600,6699ff&chls=1,1,0|1,1,0&nonsense=gmnt_io.png)

GMount is more complex than SSHFS-MUX, but still very easy to use comparing to other conventional distributed file systems. Here we only present its [usage](GMount.md), the detailed design and evaluation can be found in following publications:
  * _Nan Dun, Kenjiro Taura, Akinori Yonezawa_. GMount: An Ad Hoc and Locality-Aware Distributed File System by Using SSH and FUSE. In Proceedings of The 9th IEEE/ACM International Symposium on Cluster Computing and the Grid (CCGrid '09). ([pdf](http://portal.acm.org/citation.cfm?id=1577903))

---

`*`_The project is supported by MEXT Grant-in-Aid for Scientific Research on Priority Areas project "New IT Infrastructure for the Information-explosion Era" and Grant-in-Aid for Specially Promoted Research._