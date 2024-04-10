## Introduction

参考 [Forescout/bgp_boofuzzer](https://github.com/Forescout/bgp_boofuzzer/tree/master) 的结构特化了一个 OSPF 版本

记录日志：

```text
config
(config) log file /var/log/frr/ospfd.log debugging
(config) debug ospf te
(config) exit
```