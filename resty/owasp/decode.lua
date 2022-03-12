local _M = {}

local hdec   = require "resty.htmlentities"
local ffi    = require "ffi"
local util   = require "owasp.util"
require "resty.core.regex"
require "resty.core.hash"
require "resty.core.uri"

local ffi_cpy    = ffi.copy
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local c_buf_type = ffi.typeof("char[?]")

local string_find   = string.find
local string_gmatch = string.gmatch
local string_gsub   = string.gsub
local string_len    = string.len
local string_lower  = string.lower
local string_match  = string.match
local string_sub    = string.sub
local string_char   = string.char
local string_format = string.format
local string_byte   = string.byte

local ngx_re_match = ngx.re.match
local ngx_re_gsub = ngx.re.gsub
local ngx_re_sub = ngx.re.sub
local ngx_sha1_bin = ngx.sha1_bin
local ngx_md5 = ngx.md5
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
local ngx_unescape_uri  = ngx.unescape_uri

ffi.cdef[[
int js_decode(unsigned char *input, long int input_len);
int css_decode(unsigned char *input, long int input_len);
]]


hdec.new() 

local loadlib = function()
    local so_name = 'libdecode.so'
    local cpath = package.cpath

    for k, v in string_gmatch(cpath, "[^;]+") do
        local so_path = string_match(k, "(.*/)")
        if so_path then
            so_path = so_path .. so_name

            local f = io.open(so_path)
            if f ~= nil then
                io.close(f)
                return ffi.load(so_path)
            end
        end
    end
end
local decode_lib = loadlib()

local function decode_buf_helper(value, len)
    local buf = ffi_new(c_buf_type, len)
    ffi_cpy(buf, value)
    return buf
end


-- 编码十六进制
local function hex_encode(str)
    return (str:gsub('.', function (c)
        return string_format('%02x', string_byte(c))
    end))
end

-- 解码十六进制
local function hex_decode(str)
    local value

    if (pcall(function()
        value = str:gsub('..', function (cc)
        return string_char(tonumber(cc, 16))
        end)
    end)) then
        return value
    else
        return str
    end
end

_M.operation = {
    uri_decode = function(value)
        if not value then return end
        return ngx_unescape_uri(value)
    end,
    sha1 = function(value)
        if not value then return end
        return ngx_sha1_bin(value)
    end,
    length = function(value)
        if not value then return end
        return string_len(tostring(value))
    end,
    lowercase = function(value)
        if not value then return end
        return string_lower(tostring(value))
    end,
    md5 = function(value)
        if not value then return end
        return ngx_md5_bin(value)
    end,
    remove_comments = function(value)
        if not value then return end
        return ngx_re_gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], '', 'oij')
    end,
    remove_comments_char = function(value)
        if not value then return end
        return ngx_re_gsub(value, [=[\/\*|\*\/|--|#]=], '', 'oij')
    end,
    remove_nulls = function(value)
        if not value then return end
        return ngx_re_gsub(value, [[\0]], '', 'oij')
    end,
    remove_whitespace = function(value)
        if not value then return end
        return ngx_re_gsub(value, [=[\s+]=], '', 'oij')
    end,
    trim = function(value)
        if not value then return end
        return ngx_re_gsub(value, [=[^\s*|\s+$]=], '')
    end,
    trim_left = function(value)
        if not value then return end
        return ngx_re_sub(value, [=[^\s+]=], '')
    end,
    trim_right = function(value)
        if not value then return end
        return ngx_re_sub(value, [=[\s+$]=], '')
    end,
    base64_decode = function(value)
        if not value then return end
        --判断是否是base64编码
        --if ngx_re_match(value,"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$") ~= nil then
            if type(value) == "string" then 
                local t_val = ngx_decode_base64(value)
                if t_val then
                    return t_val
                else
                    return value
                end
            end
            return value
    end,
    base64_encode = function(value)
        if not value then return end
            local t_val = ngx_encode_base64(value)
            return t_val
    end,
    css_decode = function(value)
        if not value then return end

            if not value then return end

            local len = #value
            local buf = decode_buf_helper(value, len)

            local n = decode_lib.css_decode(buf, len)

            return (ffi_str(buf, n))
    end,
    cmd_line = function(value)
        if not value then return end
            local str = tostring(value)
            str = ngx_re_gsub(str, [=[[\\'"^]]=], '',  'oij')
            str = ngx_re_gsub(str, [=[\s+/]=],    '/', 'oij')
            str = ngx_re_gsub(str, [=[\s+[(]]=],  '(', 'oij')
            str = ngx_re_gsub(str, [=[[,;]]=],    ' ', 'oij')
            str = ngx_re_gsub(str, [=[\s+]=],     ' ', 'oij')
            return string_lower(str)
    end,
    compress_whitespace = function(value)
        if not value then return end
            return ngx_re_gsub(value, [=[\s+]=], ' ', 'oij')
    end,
    hex_decode = function(value)
        if not value then return end
            return hex_decode(value)
    end,
    hex_encode = function(value)
        if not value then return end
            return hex_encode(value)
    end,
    html_decode = function(value)
        if not value then return end
            local str = hdec.decode(value)
            return str
    end,
    js_decode = function(value)
        if not value then return end

        local len = #value
        local buf = decode_buf_helper(value, len)

        local n = decode_lib.js_decode(buf, len)

        return (ffi_str(buf, n))
    end,
    normalise_path = function(value)
        if not value then return end
        while (ngx.re.match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], 'oij')) do
            value = ngx_re_gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', 'oij')
        end
        return value
    end,
    normalise_path_win = function(value)
        if not value then return end
        value = string_gsub(value, [[\]], [[/]])
        return _M.lookup['normalise_path'](value)
    end,
    replace_comments = function(value)
        if not value then return end
        return ngx_re_gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], ' ', 'oij')
    end,
    replace_nulls = function(value)
        if not value then return end
        return ngx_re_gsub(value, [[\0]], ' ', 'oij')
    end,
    sql_hex_decode = function(value)
        if not value then return end
        if string_find(value, '0x', 1, true) then
            value = string_sub(value, 3)
            return hex_decode(value)
        else
            return value
        end
    end,
}

return _M
