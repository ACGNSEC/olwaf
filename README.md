# olwaf
基于openresty+lua实现的web应用防火墙，开源中...

功能概览：
![image](https://user-images.githubusercontent.com/12556786/111026118-94cb3800-8423-11eb-8257-61e2e87ce055.png)



用户自定义规则：

多条规则&的关系，可以实现跨access、header、body阶段匹配

模式：拦截、记录、放行

威胁等级：无威胁、warn、citical

使用范围：全局或指定域名

匹配条件：字符串包含/不包含/相等/不等/正则，长度相等/大小于、ip匹配/网段

匹配粒度：
URI  
解码后路径  
Query  
GET参数  
Method  
Host  
完整Cookie  
Cookie参数  
User Agent  
Referer  
Content-Type  
Origin  
Session  
完整HTTP header  
HTTP请求头  
HTTP请求头长度  
HTTP请求体长度  
POST参数  
上传的文件名  
完整body  
HTTP状态码  
响应内容  