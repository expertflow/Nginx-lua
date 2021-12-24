
# nginx-lua
This repository contains the configuration for the mitigation of log4j vulnerabilities in the JAVA application. Nginx with the help of lua module will prevent the attacker to access vulnerable JAVA application


## Description
This implementation will provide a quick fix for the vulnerability [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228). Expertflow latest release is not vulnerable to this vulnerability and we recommend you to update to the latest release. However, this is also one way to mitigate the risk of remote code execution with the help of Nginx + lua module. After this implementation, each request will be inspected by Nginx and if the request has exploit to remotely execute the code in either its header or in the body, the request will be dropped and won't make its way to the internal Expertflow application. 


## Requirements
1. Expertflow has built Debian-based Nginx image with lua module build-in. Just pull the docker image of nginx from the Expertflow Dockerhub registry.
2. Update the `nginx.conf` file
3. Clone and mount the `nginx-lua.conf` `lua.conf`, and `cve_2021_44228.lua` files to your nginx container.




## Implementation Steps
1. Clone and copy the `nginx-lua.conf`, `lua.conf`, and `cve_2021_44228.lua` ,  in the `/path/to/release/docker/nginx/`
2. Update the `/path/to/release/docker/nginx/https-singleton.conf` file. Add the following code in `https-singleton.conf`
```
############## lua conf################
    set $captured_request_headers "";
    set $captured_request_body "";
    set $cve_2021_44228_log "";
    rewrite_by_lua_block {
        cve_2021_44228.block_cve_2021_44228()

 }
###########################################
````
3. Now we need to update the `/path/to/release/active/docker-compose-service-gateway.yml` file. 
- Update the `image:` entry with the `expertflow/nginx-lua:debian-1.21.4`
