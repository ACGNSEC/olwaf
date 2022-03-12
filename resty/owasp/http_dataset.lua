local _M = {}

local request     = require "owasp.request"
local decode      = require "owasp.decode"
local optl         = require("optl")

local crs_decode_types = {[1] = "uri_decode", [2] = "html_decode", [3] = "replace_comments", [4] = "hex_decode", [5] = "remove_nulls" ,[6] = "js_decode", [7] = "css_decode", [8] = "lowercase", [9] = "normalise_path", [10] = "cmd_line", [11] = "compress_whitespace"}
local crs_decode_switch = true




local function multiple_decode(dataset, decode_array)
    local t = {}
    if decode_array ~= nil and dataset ~= nil then
        if type(decode_array) == "table" then
            t = dataset

            for k, v in ipairs(decode_array) do
                t = multiple_decode(t, decode_array[k])
            end
        else
             --如果dataset是table类型 循环把value添加到t表中
            if type(dataset) == "table" then
                for k, v in pairs(dataset) do
                    if type(dataset[k]) == "string" then 
                        t[k] = multiple_decode(dataset[k], decode_array)
                    end
                end
            else
                --否则直接返回
                --如果dataset为nil 不进行transform
                if not dataset then
                    return dataset 
                end
                
                return decode.operation[decode_array](dataset)
            end
        end
        return t
    end
end


_M.parse_phase = {
    access = function(dataset, ctx)
 
        local request_headers     = ngx.req.get_headers()
        local request_var         = ngx.var.request
        local request_method      = ngx.req.get_method()

        --req.get_uri_args 为table  例如请求参数 aaa=123 
        local request_uri_args    = ngx.req.get_uri_args()

        --var.request_uri 带请求参数的uri eg: /index.html?aaa=123
        local request_uri         = ngx.var.request_uri

        local request_body        = request.parse_request_body(request_headers, dataset)

        --local request_cookies   = request.cookies() or {}
        local request_cookies     = ngx.unescape_uri(ngx.var.http_cookie) or {}
        local request_common_args = request.common_args({ request_uri_args, request_body, request_cookies })

        --query_string 为?后面的参数
        local query_string        = ngx.var.query_string
        local query_str_size      = query_string and #query_string or 0
        local body_size           = ngx.var.http_content_length and tonumber(ngx.var.http_content_length) or 0

        if crs_decode_switch == true then 
            dataset.URI               = multiple_decode(ngx.var.uri, crs_decode_types)
            dataset.URI_ARGS          = request_uri_args
            dataset.QUERY_STRING      = multiple_decode(query_string, crs_decode_types)
            dataset.REQUEST_URI       = multiple_decode(request_uri, crs_decode_types)
            dataset.REQUEST_URI_RAW   = multiple_decode(request_uri_raw, crs_decode_types)
            dataset.COOKIES           = multiple_decode(request_cookies, crs_decode_types)
            dataset.REQUEST_BODY      = multiple_decode(request_body, crs_decode_types)
            dataset.REQUEST_ARGS      = multiple_decode(request_common_args, crs_decode_types)
            dataset.REQUEST_LINE      = multiple_decode(request_var,alltransform)
        else
            dataset.URI               = ngx.var.uri
            dataset.URI_ARGS          = request_uri_args
            dataset.QUERY_STRING      = query_string
            dataset.REQUEST_URI       = request_uri
            dataset.REQUEST_URI_RAW   = request_uri_raw
            dataset.COOKIES           = request_cookies
            dataset.REQUEST_BODY      = request_body, crs_decode_types
            dataset.REQUEST_ARGS      = request_common_args
            dataset.REQUEST_LINE      = request_var
        end

        dataset.SCHEME            = ngx.var.scheme
        dataset.REMOTEIP          = ngx.var.remote_addr
        dataset.IP                = ngx.var.remote_addr
        dataset.SERVERIP          = ngx.var.server_addr
        dataset.http_host         = ngx.unescape_uri(ngx.var.http_host)

        local server_name         = ngx.var.server_name
        dataset.SERVER_NAME       = server_name
        dataset.HOST              = server_name
        dataset.METHOD            = request_method
        dataset.REFERER           = ngx.unescape_uri(ngx.var.http_referer)
        dataset.USERAGENT         = ngx.unescape_uri(ngx.var.http_user_agent)
        dataset.HEADERS           = request_headers

        local headers_data
        if ngx.var.server_protocol ~= "HTTP/2.0" then
            headers_data           = ngx.unescape_uri(ngx.req.raw_header(false))
            dataset.HEADERS_DATA   = headers_data
        end

        --dataset.args             = ngx.req.get_uri_args()
        dataset.ARGS_DATA          = ngx.unescape_uri(optl.get_table(args))
        dataset.NGX_VAR            = ngx.var
        dataset.MATCHED_VARS       = {}
        dataset.MATCHED_VAR_NAMES  = {}
        dataset.ARGS_COMBINED_SIZE = query_str_size + body_size
    end,
    header_filter = function(dataset)
        local response_headers   = ngx.resp.get_headers()
        dataset.RESPONSE_HEADERS = response_headers
        dataset.STATUS           = ngx.status
    end,
    log = function() end
}

return _M
