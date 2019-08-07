# ddns_qcloud
提供了一个自动更新腾讯云域名解析记录的脚本，动态IP必备。这边假设主域名、子域名、解析记录都事先有了。这些都简单，要加新功能看官网API就行了。代码中的签名算法盗的官方demo，网上没找到能用的，真坑。

## 使用方法
1. 填写 secret_id,secret_key,domain,subDomain
2. 直接输入命令 python ddns_zq.py

## 环境
python3


