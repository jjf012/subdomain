# subdomain
一个基于python3 asyncio的高性能子域名枚举工具

扫描`qq.com`的速度`315 Found| 229612 scanned in 208.5 seconds`

> 主要借鉴了lijiejie的[subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)工作流程和字典
> 所以可以递归扫描子域名

> 参考[ESD](https://github.com/FeeiCN/ESD)的字典生成方式

需要根据使用环境修改`db\servers.txt`里面的dns服务器地址以达到最佳速度
