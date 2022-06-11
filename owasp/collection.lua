local _M = {}

--require "resty.core.regex"
local cjson  = require "cjson"
local stool   = require "stool"

local string_find   = string.find
local string_gmatch = string.gmatch
local string_gsub   = string.gsub
local string_match  = string.match
local string_sub    = string.sub


-- 参数table包含keys 返回一个table
function _M.table_keys(table)
    if type(table) ~= "table" then
        stool.fatal_fail(type(table) .. " was given to table_keys!")
    end

    local t = {}
    local n = 0

    for key, _ in pairs(table) do
        n = n + 1
        t[n] = tostring(key)
    end
    return t
end

-- 参数table包含values 返回一个table 
function _M.table_values(table)
    if type(table) ~= "table" then
        stool.fatal_fail(type(table) .. " was given to table_values!")
    end

    local t = {}
    local n = 0

    for _, value in pairs(table) do
        -- 如果一个table的vaule为table 将它拆开单独添加
        -- eg: 请求url参数 ?foo=bar&foo=bar2
        if type(value) == "table" then
            for _, values in pairs(value) do
                n = n + 1
                t[n] = tostring(values)
            end
        else
            n = n + 1
            t[n] = tostring(value)
        end
    end

    return t
end

-- 若table存在key返回真
function _M.table_has_key(needle, haystack)
    if type(haystack) ~= "table" then
        stool.fatal_fail("Cannot search for a needle when haystack is type " .. type(haystack))
    end
    return haystack[needle] ~= nil
end

-- 若table存在value返回真
function _M.table_has_value(needle, haystack)
    if type(haystack) ~= "table" then
        stool.fatal_fail("Cannot search for a needle when haystack is type " .. type(haystack))
    end

    for _, value in pairs(haystack) do
        if value == needle then
            return true
        end
    end

    return false
end

-- 选取dynamic data from storage key
function _M.dynamic_pattern(key, collection)
    local find_func = function(src)
        local val, specific
        local dot = string_find(src, "%.", 5)
        if dot then
            val = string_sub(src, 3, dot - 1)
            specific = string_sub(src, dot + 1, -2)
        else
            val = string_sub(src, 3, -2)
        end

        local val_c = collection[val]

        if type(val_c) == "table" then
            if specific then
                return val_c[specific] and tostring(val_c[specific]) or tostring(val_c[string.lower(specific)])
            else
                return val
            end
        else
            return val_c
        end
    end

    local str = string_gsub(key, "%%%b{}", find_func)
    return tonumber(str) and tonumber(str) or str
end


-- 将JSON解析为rulesset
function _M.parse_ruleset(data)
    local jdata

    if pcall(function() jdata = cjson.decode(data) end) then
        return jdata, nil
    else
        return nil, "could not decode " .. data
    end
end

-- 找到一个后缀为.json的文件 读取它返回json字符串
local function load_ruleset_file(name)
    for k, v in string_gmatch(package.path, "[^;]+") do
        local path = string_match(k, "(.*/)")

        local full_name = path .. "rules/" .. name .. ".json"

        local f = io.open(full_name)
        if f ~= nil then
            local data = f:read("*all")
            f:close()
            return _M.parse_ruleset(data)
        end
    end
    return nil, "could not find " .. name
end

_M.load_ruleset_file

-- 通过反转IPv4地址的八位字节 其添加到rbl服务器名称之前，构建RBLDNS查询
-- 解析collection基于给定的指令
_M.parse_collection = {
    specific = function(collection, value)
        return collection[value]
    end,
    regex = function(collection, value)
            local v
            local n = 0
            local _collection = {}
            for k, _ in pairs(collection) do
                if stool.remath_ext(k, value, "oij") then
                v = collection[k]
                if type(v) == "table" then
                    for __, _v in pairs(v) do
                        n = n + 1
                        _collection[n] = _v
                    end
                else
                    n = n + 1
                    _collection[n] = v
                end
            end
        end
        return _collection
    end,
    keys = function(collection)
        return _M.table_keys(collection)
    end,
    values = function(collection)
        return _M.table_values(collection)
    end,
    all = function(collection)
        local n = 0
        local _collection = {}
        for _, key in ipairs(_M.table_keys(collection)) do
	    n = n + 1
            _collection[n] = key
        end
        for _, value in ipairs(_M.table_values(collection)) do
            n = n + 1
            _collection[n] = value
        end
        return _collection
    end
}

local function ignore_regex_collection = {
    ignore = function(collection, value)
        collection[value] = nil
    end,
    regex = function(collection, value)
        for k, _ in pairs(collection) do
            if ngx.re.find(k, value, "oij") then
                collection[k] = nil
            end
        end
    end,
}
_M.ignore_regex_collection

return _M
