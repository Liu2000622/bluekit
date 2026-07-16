# -*- coding: utf-8 -*-
"""
内存马研判：识别注入型内存马的「容器扩展点 + 恶意行为」组合，给出研判结论。覆盖三种运行时：
  - Java：在 class 结构解析基础上，识别 Filter/Servlet/Listener/Valve/Interceptor/
    Controller/Agent/ClassLoader 注入型；
  - .NET/IIS：从 PE/程序集字符串识别 IHttpModule/IHttpHandler/HttpApplication 注入；
  - PHP：从源码识别 register_shutdown_function 等常驻化与框架路由注入。

判定偏保守——「扩展/持久化点」与「恶意行为」同时命中才判定为内存马，避免把正常业务
组件误判；只命中扩展点、无恶意行为的，降级为「疑似组件、待人工确认」。
"""

from wsat.report.class_decompiler import parse_class

# 内存马类型：容器扩展点特征。(类型名, 接口/父类关键词, 关键方法名)。关键词均小写、以 / 分隔。
_MEMSHELL_TYPES = [
    ("Servlet 型", ("httpservlet", "genericservlet"), ("service", "doget", "dopost")),
    ("Filter 型", ("servlet/filter",), ("dofilter",)),
    ("Listener 型", ("servletrequestlistener", "servletcontextlistener", "httpsessionlistener"),
     ("requestinitialized",)),
    ("Tomcat Valve 型", ("valvebase", "catalina/valve"), ("invoke",)),
    ("Spring Interceptor 型", ("handlerinterceptor",), ("prehandle",)),
    ("Spring Controller 型", ("requestmapping", "restcontroller", "controlleradvice"), ()),
    ("Java Agent 型", ("instrumentation",), ("premain", "agentmain")),
    ("ClassLoader 注入型", ("java/lang/classloader",), ("defineclass",)),
]

# 恶意/敏感行为。(行为名, 关键词)。前三类视为「恶意行为」，触发内存马判定。
_MALICIOUS = ("命令执行", "反射/字节码注入", "加密通信")
_BEHAVIORS = [
    ("命令执行", ("java/lang/runtime", "processbuilder", "/bin/sh", "/bin/bash", "cmd/exe", "getruntime")),
    ("反射/字节码注入", ("getdeclaredmethod", "setaccessible", "defineclass", "getmethod", "java/lang/reflect")),
    ("加密通信", ("javax/crypto", "cipher", "base64")),
    ("请求/回显操控", ("getheader", "getparameter", "getwriter", "getsession", "getrequest",
                 "getresponse", "addheader")),
    ("文件操作", ("fileoutputstream", "randomaccessfile", "java/nio/file")),
    ("数据库访问", ("java/sql", "drivermanager", "getconnection")),
    ("网络回连", ("java/net/socket", "urlconnection")),
]


# --- .NET / IIS 内存马（PE/程序集字符串匹配，保留 '.'）---
_DOTNET_TYPES = [
    ("IIS HttpModule 型", ("ihttpmodule", "registermodule")),
    ("IIS HttpHandler 型", ("ihttphandler", "ihttphandlerfactory")),
    ("HttpApplication 型", ("httpapplication", "global.asax", "beginrequest")),
]
_DOTNET_MALICIOUS = ("命令执行", "反射/程序集加载")
_DOTNET_BEHAVIORS = [
    ("命令执行", ("system.diagnostics.process", "processstartinfo", "cmd.exe", "powershell", "/c ")),
    ("反射/程序集加载", ("assembly.load", "appdomain", "system.reflection", "methodinfo.invoke")),
    ("加密通信", ("aesmanaged", "rijndaelmanaged", "convert.frombase64string",
             "system.security.cryptography")),
    ("请求/回显操控", ("httpcontext", "request.headers", "response.write", "response.headers")),
    ("文件操作", ("system.io.file", "filestream")),
]

# --- PHP 内存马（源码文本；持久化/框架注入型 + 动态执行/命令执行）---
_PHP_TYPES = [
    ("PHP 常驻/持久化型", ("register_shutdown_function", "set_error_handler",
                     "set_exception_handler", "register_tick_function",
                     "stream_wrapper_register", "auto_prepend_file")),
    ("PHP 框架路由注入型", ("addroute", "->group(", "middleware", "think\\", "illuminate\\")),
]
_PHP_MALICIOUS = ("命令执行", "动态执行")
_PHP_BEHAVIORS = [
    ("命令执行", ("system(", "shell_exec(", "passthru(", "proc_open(", "popen(", "exec(")),
    ("动态执行", ("eval(", "assert(", "create_function(", "call_user_func")),
    ("加密通信", ("base64_decode(", "gzinflate(", "str_rot13(", "openssl_decrypt(")),
    ("请求/回显操控", ("$_server", "$_request", "$_post", "$_get", "header(")),
]

_LANG_LABEL = {"java": "Java", "dotnet": ".NET/IIS", "php": "PHP"}
_LANG_MALICIOUS = {"java": _MALICIOUS, "dotnet": _DOTNET_MALICIOUS, "php": _PHP_MALICIOUS}
# 触发高置信度的「强恶意行为」（命令执行 / 反射注入 / 动态执行）
_STRONG = {"命令执行", "反射/字节码注入", "反射/程序集加载", "动态执行"}


def _haystack(info):
    """把类名/父类/接口/方法/字符串合并为可检索文本，点号归一为 /，便于统一匹配。"""
    parts = [info["class"], info["super"], *info["interfaces"]]
    parts += [n for n, _ in info["methods"]]
    parts += [d for _, d in info["methods"]]
    parts += info["strings"]
    return " ".join(p for p in parts if p).lower().replace(".", "/")


def analyze_memshell(data):
    """
    对载荷做内存马研判，返回 dict 或 None（非可识别内存马载荷）：
      {is_memshell, language, types, behaviors, confidence: high|medium|low|None, verdict}
    Java class 走结构解析；否则按 .NET/PHP 文本特征识别（无扩展点特征则返回 None）。
    """
    info = parse_class(data)
    if info:
        method_names = {n.lower() for n, _ in info["methods"]}
        hay = _haystack(info)
        types = [name for name, refs, methods in _MEMSHELL_TYPES
                 if any(r in hay for r in refs) or any(m in method_names for m in methods)]
        behaviors = [b for b, keys in _BEHAVIORS if any(k in hay for k in keys)]
        return _build_result("java", types, behaviors, info["class"])

    # 非 class：按文本识别 .NET / PHP 内存马
    text = (data.decode("latin1", "ignore") if isinstance(data, (bytes, bytearray))
            else str(data)).lower()
    for lang, types_tbl, beh_tbl in (("dotnet", _DOTNET_TYPES, _DOTNET_BEHAVIORS),
                                     ("php", _PHP_TYPES, _PHP_BEHAVIORS)):
        types = [name for name, kws in types_tbl if any(k in text for k in kws)]
        if not types:
            continue
        behaviors = [b for b, kws in beh_tbl if any(k in text for k in kws)]
        return _build_result(lang, types, behaviors, None)
    return None


def _build_result(language, types, behaviors, name):
    malicious_set = _LANG_MALICIOUS[language]
    malicious = [b for b in behaviors if b in malicious_set]
    is_mem = bool(types) and bool(malicious)
    if is_mem and any(b in _STRONG for b in behaviors):
        confidence = "high"
    elif is_mem:
        confidence = "medium"
    elif types:
        confidence = "low"   # 只命中扩展点、无恶意行为：疑似组件
    else:
        confidence = None
    return {
        "is_memshell": is_mem,
        "language": language,
        "types": types,
        "behaviors": behaviors,
        "confidence": confidence,
        "verdict": _conclusion(language, types, behaviors, is_mem, malicious_set, name),
    }


def _conclusion(language, types, behaviors, is_mem, malicious_set, name):
    """生成一句话研判结论。"""
    label = _LANG_LABEL.get(language, language)
    if not types:
        return "未见扩展点特征，非典型内存马。"
    where = "、".join(t.replace(" 型", "").replace(f"{label} ", "") for t in types)
    acts = "、".join(b for b in behaviors if b in malicious_set) or "未见明显恶意行为"
    tail = f"（类 {name}）" if name else ""
    if is_mem:
        return f"注册为 {where} 的 {label} 内存马，具备 {acts} 能力{tail}。"
    return f"实现了 {where} 扩展点但未见明显恶意行为，疑似内存马组件，建议人工确认{tail}。"


def format_verdict(result):
    """把研判结果渲染为报告/GUI 展示文本；非内存马返回 None。"""
    if not result or result.get("confidence") is None:
        return None
    label = _LANG_LABEL.get(result.get("language", "java"), "")
    conf_cn = {"high": "高", "medium": "中", "low": "低"}[result["confidence"]]
    lines = []
    if result["is_memshell"]:
        lines.append(f"⚠ 判定：{label} 内存马（置信度：{conf_cn}）")
    else:
        lines.append(f"疑似 {label} 内存马组件（置信度：{conf_cn}，需人工确认）")
    if result["types"]:
        lines.append("类型：" + "、".join(result["types"]))
    if result["behaviors"]:
        lines.append("行为：" + "、".join(result["behaviors"]))
    lines.append("结论：" + result["verdict"])
    return "\n".join(lines)
