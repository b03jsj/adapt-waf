# adapt-waf
A HTTP Protocol Waf Detection；Designed with minimal resource footprint and rapid response, the Layer 7 WAF enables dynamic tuning of interception parameters to align with specific business needs

## Install
First of all, you need OpenResty

If you plan to run this project on an existing OpenResty installation, you can refer to the nginx.conf and server.conf files in the script directory to load the project into OpenResty.

The entry point of the project is waf/init.lua.

Alternatively, you can use the install.sh script in the resources directory to install the project on a fresh OpenResty environment.

The project currently supports protection against SQL injection (SQLi) and XSS attacks.
More Layer 7 security features are planned, including a web-based configuration interface and interception log visualization.

## waf/init.lua
init_worker: load and initialize weights into lua_shared_dict

access： At the access phase, the client IP is evaluated against the configured blacklist to determine if the request should be denied.

log： At the log phase, the request payload is minimally tokenized and evaluated using a weight-based scoring model. Requests that hit the blocking range are recorded and used to update the blacklist.

## shard.dict
# 攻击训练
lua_shared_dict waf_train 20m;
# 攻击样本token权重
lua_shared_dict waf_w 20m;
# 样本置信度
lua_shared_dict waf_c 20m;
# 拦截
lua_shared_dict waf_block 20m;

## Performance
~25 ms per request for 100 parameters (30 characters each).
Lower payload complexity results in faster processing.
