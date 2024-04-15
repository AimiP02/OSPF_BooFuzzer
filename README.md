## Introduction

参考 [Forescout/bgp_boofuzzer](https://github.com/Forescout/bgp_boofuzzer/tree/master) 的结构特化了一个 OSPF 版本

## Installation

docker 配置文件放置在`frrouter-docker`中，使用`docker-compose up -d`即可启动容器，docker 配置的路由环境如下

![](./img/fig2.png)

fuzzer 运行在 frrouter1 上，对 frrouter2 发送 fuzzing 包

```bash
# frrouter2
docker exec -it frrouter2 fish
cd /home/fuzzer

python3 main.py --ip [frrouter2's eth1 ip] --port 1122 --monitor frr
```

等待 frr 服务重启后，watchfrr 和 boofuzz 的 procmon 会监控 ospfd 的存活情况，此时可以进行 fuzz 了

```bash
# frrouter1
docker exec -it frrouter1 fish
cd /home/fuzzer

python3 fuzz_xxx.py --route_id [frrouter1's eth1 ip] --area_id 0.0.0.0 --tip [frrouter2's eth1 ip] --trpc_port 1122
```