-- -*- location: /etc/nginx/conf.d/cve_2021_44228.lua; -*-
-- -*- mode: lua; -*-
-- -*- author: John H Patton; -*-
-- -*- email: jhpattonconsulting@gmail.com; -*-
-- -*- license: MIT License; -*-
--
-- Copyright 2021 JH Patton Consulting, LLC
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy of this
-- software and associated documentation files (the "Software"), to deal in the Software
-- without restriction, including without limitation the rights to use, copy, modify,
-- merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
-- permit persons to whom the Software is furnished to do so, subject to the following
-- conditions:
-- 
-- The above copyright notice and this permission notice shall be included in all copies
-- or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
-- INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
-- PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
-- LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
-- OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-- DEALINGS IN THE SOFTWARE.
-- Version: 1.0

local _M = {}

-- pattern to match beginning of jndi command in a matcher
local cve_2021_44228 = '%$%{jndi:'

-- pattern to capture XXX from a ${XXX} group in a matcher
local cve_2021_44228_group = '%%b{}'

-- validate captured XXX group for substring patterns
-- ${lower:j}
-- ${upper:j}
local cve_2021_44228_badness = '%$%{[^:]+:[jndiJNDI:]+%}'
 

-- validate captured XXX group for substring patterns
-- ${::-j}
-- ${::-n}
-- ${::-d}
-- ${::-i}
-- ${::-:}
local cve_2021_44228_more_badness = '%$%{[^:]*:[^:]*:%-?[jndiJNDI:]+%}'

-- validate captured XXX group for substring patterns
-- looks for nested commands:
--  ${en${lower:v}:ENV_NAME:-j}
--  ${lower:${upper:${lower:${upper:${lower:${upper:${lower:${upper:${lower:${upper:${lower:${upper:${lower:j}}}}}}}}}}}}}
local cve_2021_44228_double_trouble ='%$%{[^$]*%$%{.+%}.+%}'
-- local custom_regex_1 = '\$\{\s*(j|\$?\{.+?\})'


local function isempty(s)
  return s == nil or s == ''
end

-- capture the request body
-- NOTE: set an nginx variable: captured_request_body
local function capture_request_body()
  if isempty(ngx.var.captured_request_body) then
    ngx.req.read_body()
    local request_body = ngx.req.get_body_data()
    if isempty(request_body) then
      -- body may get buffered in a temp file:
      local body_file = ngx.req.get_body_file()
      if not isempty(body_file) then
        local body_file_handle, err = io.open(body_file, "r")
        if body_file_handle then
          body_file_handle:seek("set")
          request_body = body_file_handle:read("*a")
          ngx.log(ngx.ERR, "BODY DATA START")
          ngx.say(request_body)
          ngx.log(ngx.ERR, "BODY DATA END")
          body_file_handle:close()
        else
          request_body = ""
          ngx.log(ngx.ERR, "failed to open request body file or failed for reading, check system." )
        end
      else
        request_body = ""
      end -- if not isempty(body_file)
    end -- isempty(request_body) -- file block
    ngx.var.captured_request_body = request_body
  end -- isempty(ngx.var.captured_request_body)
end -- function

-- capture the request headers
-- NOTE: set an nginx variable: captured_request_headers
function capture_request_headers()
  if isempty(ngx.var.captured_request_heders) then
    local ngh = ngx.req.get_headers()
    if not isempty(ngh) then
      local request_headers = ""
      for k, v in pairs(ngh) do
        if (type(v) == "table") then
          for k2, v2 in pairs(v) do
            if isempty(request_headers) then
              request_headers = '"' .. k2 .. '":"' .. v2 .. '"'
            else
              request_headers = request_headers .. ',"' .. k2 .. '":"' .. v2 .. '"'
            end
          end
        else
          if isempty(request_headers) then
            request_headers = '"' .. k .. '":"' .. v .. '"'
          else
            request_headers = request_headers .. ',"' .. k .. '":"' .. v .. '"'
          end
        end -- if (type(v)
      end -- for k, v
      ngx.var.captured_request_headers = request_headers 
    end -- if not isempty(ngh)
  end -- if isempty(ngx.var.captured_request_headers) -- only needs to be captured once
end -- function


function _M.block_cve_2021_44228()
  local match = ""
  local first, last = 0

  capture_request_headers()
  capture_request_body()
  local request = ngx.var.request .. ';;' .. ngx.var.captured_request_headers
  request = ngx.unescape_uri(request)
  -- ngx.log(ngx.ERR, "CVE-2021-44228 blocked, BODY>>>>>>" .. ngx.var.captured_request_body .. "<<<<<CVE-2021-44228 blocked, BODY")
  if not isempty(ngx.var.captured_request_body) then
    request = request .. ';;' .. ngx.var.captured_request_body
    ngx.log(ngx.ERR, "Expertflow request start:::::::" .. request .. ":::::::Expertflow request end")
  end
  
  if not isempty(request) then
    if string.match(request, cve_2021_44228) then
      ngx.log(ngx.ERR, "cve-2021-44228-blocked: " .. string.match(request, cve_2021_44228))
      ngx.var.cve_2021_44228_log = "cve-2021-44228-blocked"
      -- ngx.status = ngx.HTTP_FORBIDDEN
      -- ngx.exit(ngx.HTTP_FORBIDDEN)
      ngx.say(" Expertflow Log4J Forbidden")
      ngx.exit(ngx.HTTP_OK)
    else
      while true do
        first, last = request:find(cve_2021_44228_group, first+1) 
        if not first then break end
        if string.match(request:sub(first, last), cve_2021_44228_badness) 
        or string.match(request:sub(first, last), cve_2021_44228_more_badness)
        -- or string.find(request:sub(first, last):upper(), 'JNDI')
        -- or string.find(request:sub(first, last):upper(), 'LDAP')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'JNDI')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'LDAP')
        -- or string.find(request:sub(first, last):upper(), 'RMI')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'RMI')
        -- or string.find(request:sub(first, last):upper(), 'LDAPS')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'LDAPS')
        -- or string.find(request:sub(first, last):upper(), 'DNS')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'DNS')
        -- or string.find(request:sub(first, last):upper(), 'NIS')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'NIS')
        -- or string.find(request:sub(first, last):upper(), 'NDS')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'NDS')
        -- or string.find(request:sub(first, last):upper(), 'CORBA')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'CORBA')
        -- or string.find(request:sub(first, last):upper(), 'IIOP')
        -- or string.find(ngx.var.captured_request_headers:upper(), 'IIOP')
        -- or string.find(request:sub(first, last):upper(), '%$%{JNDI:LDAP:/')
        -- or string.find(request:sub(first, last):upper(), '%$%{JNDI:RMI:/')
        -- or string.find(request:sub(first, last):upper(), '%$%{JNDI:LDAPS:/')
        -- or string.find(request:sub(first, last):upper(), '%$%{JNDI:DNS:/')
        or string.match(request:sub(first, last), cve_2021_44228_double_trouble) then
          ngx.log(ngx.ERR, "CVE-2021-44228 BLOCKED, Headers" .. ngx.var.captured_request_headers)
          ngx.log(ngx.ERR, "CVE-2021-44228 BLOCKED, BODY START::::" .. ngx.var.captured_request_body .. "::::::CVE-2021-44228 blocked, BODY END")
          ngx.log(ngx.ERR, "CVE-2021-44228-BLOCKED:>>" .. request:sub(first, last) .. "<<CVE-2021-44228-BLOCKED")
          ngx.log(ngx.ERR, "cve-2021-44228-blocked: ${ ... " .. request:sub(first, last) .. " ... }")
          ngx.var.cve_2021_44228_log = "cve-2021-44228-blocked"
          -- ngx.status = ngx.HTTP_FORBIDDEN
          -- ngx.exit(ngx.HTTP_FORBIDDEN)
          ngx.say(" Expertflow Log4J Forbidden")
          ngx.exit(ngx.HTTP_OK)
        end -- if string.match
      end -- while true
    end -- if string.match
  end -- if not isempty(request)
end -- function

return _M
-- end: cve_2021_44228.lua
