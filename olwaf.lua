-- 20220127 stan1ey --
--require "resty.core.regex"
local urlParser = require "net.url"
local request = require "request"
local cidr = require "cidr"
local OLWAF = {}


function OLWAF.checkProtocol()
    local request = ngx.var.request
    if not _Util.empty(request) then
        
        if _Util.remath_ext(request, "^(?i)(get|option|delete|put)(\\s{2,}|\\s\\/.*\\s(?!HTTP\\/(0\\.9|1\\.0|1\\.1|2\\.0)$))") then
            do_action(1, "protocol", "^(?i)(get|option|delete|put)(\\s{2,})", request)
        end
    end

end

local function compare_match(str, searchStr , case , match)
    --if str == nil or searchStr == nil or case == nil or match == nil then return false end 
    if str ~= nil and searchStr ~= nil and case ~= nil and match ~= nil then
    if type(str) == 'table' then
        str  = table.concat(str)   
    else
          
    end
    if match == "include" then
        if case then
            if string.find(str, searchStr) ~= nil then
                return true
            else
                return false
            end
        else 
            if string.find(str, searchStr) == nil then
                return true
            else
                return false
            end	
        end
    elseif match == "equal" then
        if case then
            if str == searchStr then
                return true
            end
        else
            if str ~= searchStr then
                return true
            end
        end
    elseif match == "regex" then
        if case then
            local from, to = ngx_re_find(str, searchStr, "jio")
            if from then
                return true
            end
	else
            local from, to = ngx_re_find(str, searchStr, "jio")
            if from == nil then
               return true
            end   
        end
    elseif match == "length" then
        if case == "eq" then
            if tonumber(str) == searchStr then
                return true
            end
        elseif case == "ne" then
            if tonumber(str) ~= searchStr then
                return true
            end
        elseif case == "gt" then
            if tonumber(str) > searchStr then
                return true
            end
        elseif case == "lt" then
            if tonumber(str) < searchStr then
                return true
            end
        elseif case == "ge" then
            if tonumber(str) >= searchStr then
                return true
            end
        elseif case == "le" then
            if tonumber(str) <= searchStr then
                return true
            end            
        end
    elseif match == "ipsegment" then
        local srcIpNum = _Util.ip_to_number(str)
        local ipToNumStart, ipToNumEnd = cidr.parse_cidr(searchStr)
        if case then
            if tonumber(srcIpNum) <= ipToNumEnd and tonumber(srcIpNum) >= ipToNumStart then
                return true
            else
                return false
            end
        else
            if tonumber(srcIpNum) >= ipToNumEnd or tonumber(srcIpNum) <= ipToNumStart then
                return true
            else
                return false
            end
        end
            
    end
    end

end

function OLWAF.userDefineRulesMatch(type,  re_str, matchCase, match, str_args)
    if type == nil or re_str == nil or matchCase == nil or match == nil then return false end
    local flag = false
    if type == "uri" then
        flag = compare_match(request.request['URI'](), re_str , matchCase , match)
    elseif type == "decode" then

    elseif type == "query" then--url中 ?开始到最后部分
        flag = compare_match(request.request['QUERY_STRING'](), re_str , matchCase , match)
    elseif type == "query_args" then--请求?开始到最后的部分，拆分键值对形式后进行一次url解码，指定参数获取
        flag = compare_match(request.request['URI_ARGS']()[str_args], re_str , matchCase , match)
    elseif type == "method" then
        flag = compare_match(request.request['METHOD'](), re_str , matchCase , match)
    elseif type == "host" then
        flag = compare_match(request.request['REMOTE_HOST'](), re_str , matchCase , match)
    elseif type == "all_cookie" then
        flag = compare_match(ngx.var.http_cookie, re_str , matchCase , match)
    elseif type == "cookie_args" then
        local cookieObj = cookie:new()
        local cookieValue = cookieObj:get(str_args)
        flag = compare_match(cookieValue, re_str , matchCase , match)
    elseif type == "ua" then
        flag = compare_match(request.request['HTTP_USER_AGENT'](), re_str , matchCase , match)

    elseif type == "referer" then
        flag = compare_match(request.request['HTTP_REFERER'](), re_str , matchCase , match)

    elseif type == "content-type" then
        flag = compare_match(ngx.req.get_headers()["Content-Type"], re_str , matchCase , match)
    elseif type == "content-length" then
        flag = compare_match(ngx.req.get_headers()["Content-Length"], re_str , matchCase , match)

    elseif type == "remote_ip" then
        flag = compare_match(request.request['REMOTE_ADDR'](), re_str , matchCase , match)

    elseif type == "xff" then
        flag = compare_match(ngx.req.get_headers()["X-Forwarded-For"], re_str , matchCase , match)
    elseif type == "origin" then
        flag = compare_match(ngx.var.http_origin, re_str , matchCase , match)

    elseif type == "session" then

    elseif type == "all_head" then-- 完整的http请求头
        flag = compare_match(table.concat(request.request['REQUEST_HEADERS']()), re_str , matchCase , match)
    elseif type == "head" then-- 拆分为键值对形式
        flag = compare_match(ngx.req.get_headers()[str_args], re_str , matchCase , match)
    elseif type == "head_length" then -- 请求头长度
        flag = compare_match(tostring(ngx.var.request_length), re_str , matchCase , match)
    elseif type == "post_args" then
        if _Util.checkContentType() == false then
            if request.request['ARGS_POST']() ~= nil then
                flag = compare_match(request.request['ARGS_POST']()[str_args], re_str , matchCase , match)
            end
        end
    elseif type == "uploadfile_name" then
        flag = compare_match(request.request['FILE_NAMES'](), re_str , matchCase , match)
    elseif type == "resp_body" then --body 阶段来用 获取body内容过滤
        if ngx.get_phase() == "body_filter" then
            local resp_raw_data, flag = request.request['RESP_BODY']()
            if resp_raw_data ~= nil then
                flag = compare_match(resp_raw_data, re_str , matchCase , match)
            end
        end
    elseif type == "status" then --状态码
        if ngx.get_phase() == "body_filter" then
        flag = compare_match(ngx.status, re_str , matchCase , match)
        end
    elseif type == "req_body" then
        ngx.req.read_body()
        local data = ngx.req.get_body_data()
        if data ~= nil then
            flag = compare_match(data, re_str , matchCase , match)
        end
    end
    return flag
end

function OLWAF.userDefine()
    ngx.ctx.match = {}
    for i, v in pairs(Config.userDefine.rules ) do
        local totalMatch = {}
        if v.rule and type(v.rule) == 'table' then
            local matchNum = 0
            for k, var in pairs(v.rule) do
                if OLWAF.userDefineRulesMatch(var.type, var.data, var.option, var.match, var.args) then
                    matchNum = matchNum + 1
                end
            end
            if v.num == matchNum then
                if v.action == 1 then
                    OLWAF.deny_func("userDefine", v.attackType, "deny by user define policy")
                end
            else
                ngx.ctx.match[v.ruleid] = matchNum
            end
        end
    end
    return 

end

return OLWAF
