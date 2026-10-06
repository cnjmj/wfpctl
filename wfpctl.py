#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  wfpctl.py —— Windows 过滤平台 (WFP) 过滤规则管理命令行工具 (Python 版)
#
#  与 wfpctl.exe (C# 版) 功能一致:
#    add / del / list / show / layers / sublayers / sublayer-add / sublayer-del
#
#  实现: 通过 ctypes 直接调用系统 fwpuclnt.dll (BFE 服务客户端), 无需编译、
#        无需第三方依赖, 本机数据处理。
#
#  运行: python wfpctl.py <命令> [选项]
#        增删操作需要管理员权限 (依赖 BFE 服务)。
#
#  说明: 结构体布局与官方 SDK fwpmtypes.h / fwptypes.h 严格对应,
#        程序启动时自检关键结构体尺寸 (x64: FWPM_FILTER0 = 200 字节)。
# ============================================================================

import ctypes
import socket
import struct
import sys
import uuid

# ---------------------------------------------------------------------------
# 控制台 UTF-8 输出 (真实控制台切换代码页; 重定向管道强制 UTF-8 编码)
# ---------------------------------------------------------------------------
try:
    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
except Exception:
    pass
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# ctypes 结构体定义 (fwptypes.h / fwpmtypes.h)
# ---------------------------------------------------------------------------


class GUID(ctypes.Structure):
    # 内存布局: ULONG + USHORT + USHORT + BYTE[8], 对齐 4, 大小 16
    _fields_ = [
        ("Data1", ctypes.c_uint),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint), ("data", ctypes.c_void_p)]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", ctypes.c_wchar_p), ("description", ctypes.c_wchar_p)]


class FwpValueUnion(ctypes.Union):
    # 标量内联; 指针类 (uint64*/blob/sid/v4mask/v6mask/range...) 为 c_void_p
    _fields_ = [
        ("uint8", ctypes.c_uint8),
        ("uint16", ctypes.c_uint16),
        ("uint32", ctypes.c_uint32),
        ("float32", ctypes.c_float),
        ("ptr", ctypes.c_void_p),
    ]


class FWP_VALUE0(ctypes.Structure):
    # c_uint(4) + pad(4) + union(8) = 16 字节
    _fields_ = [("type", ctypes.c_uint), ("value", FwpValueUnion)]


class FWP_RANGE0(ctypes.Structure):
    _fields_ = [("low", FWP_VALUE0), ("high", FWP_VALUE0)]


class FWPM_ACTION0(ctypes.Structure):
    # MIDL: UINT32 type + union{GUID filterType; GUID calloutKey;}
    # 实测 native 大小 24 字节 (type 后 4 字节 padding, GUID 在 offset 8)
    _fields_ = [
        ("type", ctypes.c_uint),
        ("_pad", ctypes.c_uint),
        ("calloutKey", GUID),
    ]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    # GUID(16) + matchType(4) + pad(4) + FWP_VALUE0(16) = 40 字节
    _fields_ = [
        ("fieldKey", GUID),
        ("matchType", ctypes.c_uint),
        ("conditionValue", FWP_VALUE0),
    ]


class FilterContextUnion(ctypes.Union):
    # MIDL: union { UINT64 rawContext; GUID providerContextKey; } = 16 字节
    _fields_ = [("rawContext", ctypes.c_uint64), ("providerContextKey", GUID)]


class FWPM_FILTER0(ctypes.Structure):
    _fields_ = [
        ("filterKey", GUID),                     # 0
        ("displayData", FWPM_DISPLAY_DATA0),     # 16
        ("flags", ctypes.c_uint),                # 32
        ("providerKey", ctypes.c_void_p),        # 40
        ("providerData", FWP_BYTE_BLOB),         # 48
        ("layerKey", GUID),                      # 64
        ("subLayerKey", GUID),                   # 80
        ("weight", FWP_VALUE0),                  # 96
        ("numFilterConditions", ctypes.c_uint),  # 112
        ("filterCondition", ctypes.c_void_p),    # 120
        ("action", FWPM_ACTION0),                # 128
        ("context", FilterContextUnion),         # 152
        ("reserved", ctypes.c_void_p),           # 168
        ("filterId", ctypes.c_uint64),           # 176
        ("effectiveWeight", FWP_VALUE0),         # 184
    ]                                           # 200


class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint), ("mask", ctypes.c_uint)]


class FWPM_SUB_LAYER0(ctypes.Structure):
    _fields_ = [
        ("subLayerKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint),
        ("providerKey", ctypes.c_void_p),
        ("providerData", FWP_BYTE_BLOB),
        ("weight", ctypes.c_uint16),
    ]


class FWPM_LAYER0(ctypes.Structure):
    _fields_ = [
        ("layerKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint),
        ("numFields", ctypes.c_uint),
        ("field", ctypes.c_void_p),
        ("defaultSubLayerKey", GUID),
    ]


# ---------------------------------------------------------------------------
# 常量 (fwptypes.h / fwpmtypes.h, 与 C# 版一致)
# ---------------------------------------------------------------------------
RPC_C_AUTHN_WINNT = 10

FWP_ACTION_BLOCK = 0x0001 | 0x1000
FWP_ACTION_PERMIT = 0x0002 | 0x1000

FWPM_FILTER_FLAG_PERSISTENT = 0x1
FWPM_FILTER_FLAG_BOOTTIME = 0x2
FWPM_FILTER_FLAG_DISABLED = 0x20
FWPM_FILTER_FLAG_INDEXED = 0x40

FWPM_SUBLAYER_FLAG_PERSISTENT = 0x1

FWP_MATCH_EQUAL = 0
FWP_MATCH_RANGE = 5

FWP_EMPTY = 0
FWP_UINT8 = 1
FWP_UINT16 = 2
FWP_UINT32 = 3
FWP_UINT64 = 4
FWP_INT8 = 5
FWP_INT16 = 6
FWP_INT32 = 7
FWP_INT64 = 8
FWP_FLOAT = 9
FWP_DOUBLE = 10
FWP_BYTE_ARRAY16_TYPE = 11
FWP_BYTE_BLOB_TYPE = 12
FWP_SID = 13
FWP_SECURITY_DESCRIPTOR_TYPE = 14
FWP_TOKEN_INFORMATION_TYPE = 15
FWP_UNICODE_STRING_TYPE = 17
FWP_BYTE_ARRAY6_TYPE = 18
FWP_V4_ADDR_MASK = 0x100
FWP_V6_ADDR_MASK = 0x101
FWP_RANGE_TYPE = 0x102

# ---- WFP 常量 GUID (取自官方 SDK fwpmu.h) ----
LAYER_ALE_AUTH_CONNECT_V4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"
LAYER_ALE_AUTH_CONNECT_V6 = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4"
LAYER_ALE_AUTH_RECV_ACCEPT_V4 = "e1cd9fe7-f4b5-4273-96c0-592e487b8650"
LAYER_ALE_AUTH_RECV_ACCEPT_V6 = "a3b42c97-9f04-4672-b87e-cee9c483257f"
LAYER_OUTBOUND_TRANSPORT_V4 = "09e61aea-d214-46e2-9b21-b26b0b2f28c8"
LAYER_OUTBOUND_TRANSPORT_V6 = "e1735bde-013f-4655-b351-a49e15762df0"
LAYER_INBOUND_TRANSPORT_V4 = "5926dfc8-e3cf-4426-a283-dc393f5d0f9d"
LAYER_INBOUND_TRANSPORT_V6 = "634a869f-fc23-4b90-b0c1-bf620a36ae6f"

COND_IP_PROTOCOL = "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"
COND_IP_LOCAL_ADDRESS = "d9ee00de-c1ef-4617-bfe3-ffd8f5a08957"
COND_IP_REMOTE_ADDRESS = "b235ae9a-1d64-49b8-a44c-5ff3d9095045"
COND_IP_LOCAL_PORT = "0c1ba1af-5765-453f-af22-a8f791ac775b"
COND_IP_REMOTE_PORT = "c35a604d-d22b-4e1a-91b4-68f674ee674b"
COND_ALE_APP_ID = "d78e1e87-8644-4ea5-9437-d809ecefc971"
COND_ALE_USER_ID = "af043a0a-b34d-4f86-979c-c90371af6e66"
COND_IPSEC_QM_SA_ID = "4cd62a49-59c3-4969-b7f3-bda5d32890a4"

# 本工具默认子层 (与 C# 版相同 GUID, 两版工具共用、可互相管理)
WFPCTL_SUBLAYER = "b7c4f2a1-3e5d-4a90-8b1c-6f2e7d8a9b3c"
TOOL_SUBLAYER_NAME = "wfpctl rules"

# ---- 层别名 ----
LAYER_ALIASES = [
    ("connect-v4", LAYER_ALE_AUTH_CONNECT_V4, "出站连接授权 (ALE)"),
    ("connect-v6", LAYER_ALE_AUTH_CONNECT_V6, "出站连接授权 (ALE, IPv6)"),
    ("accept-v4", LAYER_ALE_AUTH_RECV_ACCEPT_V4, "入站连接授权 (ALE)"),
    ("accept-v6", LAYER_ALE_AUTH_RECV_ACCEPT_V6, "入站连接授权 (ALE, IPv6)"),
    ("out-v4", LAYER_OUTBOUND_TRANSPORT_V4, "出站传输层"),
    ("out-v6", LAYER_OUTBOUND_TRANSPORT_V6, "出站传输层 (IPv6)"),
    ("in-v4", LAYER_INBOUND_TRANSPORT_V4, "入站传输层"),
    ("in-v6", LAYER_INBOUND_TRANSPORT_V6, "入站传输层 (IPv6)"),
]

# ---- 常见 WFP 错误码 ----
WFP_ERRORS = {
    0x80320001: "FWP_E_CALLOUT_NOT_FOUND",
    0x80320002: "FWP_E_CONDITION_NOT_FOUND (该层不支持此条件字段)",
    0x80320003: "FWP_E_FILTER_NOT_FOUND",
    0x80320004: "FWP_E_LAYER_NOT_FOUND",
    0x80320007: "FWP_E_SUBLAYER_NOT_FOUND",
    0x80320008: "FWP_E_NOT_FOUND",
    0x80320009: "FWP_E_ALREADY_EXISTS",
    0x8032000A: "FWP_E_IN_USE (子层下仍有规则)",
    0x8032000D: "FWP_E_NO_TXN_IN_PROGRESS",
    0x8032000E: "FWP_E_TXN_IN_PROGRESS",
    0x8032000F: "FWP_E_TXN_ABORTED",
    0x80320010: "FWP_E_SESSION_ABORTED",
    0x80320016: "FWP_E_LIFETIME_MISMATCH (持久过滤器必须挂在持久子层上)",
    0x8032001C: "FWP_E_NULL_POINTER",
    0x8032001D: "FWP_E_INVALID_ENUMERATOR",
    0x8032001E: "FWP_E_INVALID_FLAGS",
    0x8032001F: "FWP_E_INVALID_NET_MASK",
    0x80320020: "FWP_E_INVALID_RANGE",
    0x80320023: "FWP_E_NULL_DISPLAY_NAME",
    0x80320025: "FWP_E_INVALID_WEIGHT",
    0x80320026: "FWP_E_MATCH_TYPE_MISMATCH",
    0x80320027: "FWP_E_TYPE_MISMATCH",
    0x8032002A: "FWP_E_DUPLICATE_CONDITION",
    0x8032002C: "FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER",
}

# ---------------------------------------------------------------------------
# API 绑定
# ---------------------------------------------------------------------------
_fwpuclnt = ctypes.WinDLL("fwpuclnt.dll")
_advapi32 = ctypes.WinDLL("advapi32.dll")
_kernel32 = ctypes.WinDLL("kernel32.dll")

_HR = ctypes.c_long  # HRESULT


def _bind(name, restype=_HR, argtypes=None):
    fn = getattr(_fwpuclnt, name)
    fn.restype = restype
    if argtypes is not None:
        fn.argtypes = argtypes
    return fn


FwpmEngineOpen0 = _bind("FwpmEngineOpen0", argtypes=[
    ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p)])
FwpmEngineClose0 = _bind("FwpmEngineClose0", argtypes=[ctypes.c_void_p])
FwpmTransactionBegin0 = _bind("FwpmTransactionBegin0", argtypes=[
    ctypes.c_void_p, ctypes.c_uint])
FwpmTransactionCommit0 = _bind("FwpmTransactionCommit0", argtypes=[ctypes.c_void_p])
FwpmTransactionAbort0 = _bind("FwpmTransactionAbort0", argtypes=[ctypes.c_void_p])

FwpmFilterAdd0 = _bind("FwpmFilterAdd0", argtypes=[
    ctypes.c_void_p, ctypes.POINTER(FWPM_FILTER0), ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint64)])
FwpmFilterDeleteById0 = _bind("FwpmFilterDeleteById0", argtypes=[
    ctypes.c_void_p, ctypes.c_uint64])
FwpmFilterGetById0 = _bind("FwpmFilterGetById0", argtypes=[
    ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p)])
FwpmFilterCreateEnumHandle0 = _bind("FwpmFilterCreateEnumHandle0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
FwpmFilterEnum0 = _bind("FwpmFilterEnum0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)])
FwpmFilterDestroyEnumHandle0 = _bind("FwpmFilterDestroyEnumHandle0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p])

FwpmSubLayerAdd0 = _bind("FwpmSubLayerAdd0", argtypes=[
    ctypes.c_void_p, ctypes.POINTER(FWPM_SUB_LAYER0), ctypes.c_void_p])
FwpmSubLayerDeleteByKey0 = _bind("FwpmSubLayerDeleteByKey0", argtypes=[
    ctypes.c_void_p, ctypes.POINTER(GUID)])
FwpmSubLayerCreateEnumHandle0 = _bind("FwpmSubLayerCreateEnumHandle0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
FwpmSubLayerEnum0 = _bind("FwpmSubLayerEnum0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)])
FwpmSubLayerDestroyEnumHandle0 = _bind("FwpmSubLayerDestroyEnumHandle0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p])

FwpmLayerCreateEnumHandle0 = _bind("FwpmLayerCreateEnumHandle0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
FwpmLayerEnum0 = _bind("FwpmLayerEnum0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)])
FwpmLayerDestroyEnumHandle0 = _bind("FwpmLayerDestroyEnumHandle0", argtypes=[
    ctypes.c_void_p, ctypes.c_void_p])

FwpmFreeMemory0 = _bind("FwpmFreeMemory0", argtypes=[ctypes.POINTER(ctypes.c_void_p)])
# 该函数返回 Win32 错误码 (0 = 成功)
FwpmGetAppIdFromFileName0 = _bind(
    "FwpmGetAppIdFromFileName0", restype=ctypes.c_uint,
    argtypes=[ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)])

_advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
_advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(ctypes.c_uint)]
_kernel32.LocalFree.restype = ctypes.c_void_p
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
class WfpError(Exception):
    def __init__(self, hr, msg):
        super().__init__(msg)
        self.hr = (hr & 0xFFFFFFFF) if hr is not None else 0
        self.msg = msg


def hr_msg(hr):
    u = hr & 0xFFFFFFFF
    name = WFP_ERRORS.get(u)
    if name:
        return "%s (0x%08X)" % (name, u)
    return "0x%08X" % u


def check(hr, what):
    if hr != 0:
        raise WfpError(hr, "%s 失败: %s" % (what, hr_msg(hr)))


def guid_set(g, s):
    """把 GUID 字符串写入 GUID 结构体 (内存布局 = uuid.bytes_le)"""
    raw = uuid.UUID(s).bytes_le
    ctypes.memmove(ctypes.addressof(g), raw, 16)


def guid_str(g):
    """GUID 结构体 → GUID 字符串"""
    raw = ctypes.string_at(ctypes.addressof(g), 16)
    return str(uuid.UUID(bytes_le=raw))


def resolve_layer(s):
    """层别名/GUID 字符串 → GUID 字符串; 失败返回 None"""
    for alias, g, _ in LAYER_ALIASES:
        if s.lower() == alias:
            return g
    try:
        return str(uuid.UUID(s.strip().strip("{}")))
    except ValueError:
        return None


def layer_alias_of(gstr):
    for alias, g, _ in LAYER_ALIASES:
        if g.lower() == gstr.lower():
            return alias
    return None


def host_to_net16(p):
    return struct.unpack(">H", struct.pack("<H", p))[0]


def net_to_host16(v):
    return struct.unpack("<H", struct.pack(">H", v))[0]


def popcount(x):
    n = 0
    while x:
        n += x & 1
        x >>= 1
    return n


# ---------------------------------------------------------------------------
# BFE 内存深拷贝 (必须在 FwpmFreeMemory0 前完成, 与 C# 版相同原则)
# ---------------------------------------------------------------------------
def copy_value(v):
    """FWP_VALUE0 → (type, 托管值); 读取时 BFE 内存必须仍有效"""
    t = v.type
    if t == FWP_UINT8:
        return (t, v.value.uint8)
    if t == FWP_UINT16:
        return (t, v.value.uint16)
    if t == FWP_UINT32:
        return (t, v.value.uint32)
    if t == FWP_UINT64 or t == FWP_INT64:
        return (t, ctypes.c_int64.from_address(v.value.ptr).value)
    if t == FWP_INT32:
        return (t, ctypes.c_int32(v.value.uint32).value)
    if t == FWP_INT16:
        return (t, ctypes.c_int16(v.value.uint16).value)
    if t == FWP_INT8:
        return (t, ctypes.c_int8(v.value.uint8).value)
    if t == FWP_FLOAT:
        return (t, v.value.float32)
    if t == FWP_DOUBLE:
        return (t, ctypes.c_double.from_address(v.value.ptr).value)
    if t == FWP_BYTE_ARRAY16_TYPE:
        return (t, ctypes.string_at(v.value.ptr, 16))
    if t in (FWP_BYTE_BLOB_TYPE, FWP_SECURITY_DESCRIPTOR_TYPE):
        bb = FWP_BYTE_BLOB.from_address(v.value.ptr)
        if bb.size == 0 or not bb.data:
            return (t, b"")
        return (t, ctypes.string_at(bb.data, bb.size))
    if t == FWP_SID:
        out = ctypes.c_wchar_p()
        if _advapi32.ConvertSidToStringSidW(v.value.ptr, ctypes.byref(out)):
            s = out.value or ""
            _kernel32.LocalFree(out)
            return (t, s)
        return (t, None)
    if t == FWP_UNICODE_STRING_TYPE:
        return (t, ctypes.wstring_at(v.value.ptr))
    if t == FWP_V4_ADDR_MASK:
        m = FWP_V4_ADDR_AND_MASK.from_address(v.value.ptr)
        return (t, (m.addr, m.mask))
    if t == FWP_V6_ADDR_MASK:
        # FWP_V6_ADDR_AND_MASK = { UINT8 addr[16]; UINT8 prefixLength; }
        raw = ctypes.string_at(v.value.ptr, 17)
        return (t, (raw[:16], raw[16]))
    if t == FWP_RANGE_TYPE:
        r = FWP_RANGE0.from_address(v.value.ptr)
        return (t, (copy_value(r.low), copy_value(r.high)))
    return (t, None)


def copy_filter(p):
    """FWPM_FILTER0 指针 → 托管 dict (深拷贝, BFE 内存此时有效)"""
    f = FWPM_FILTER0.from_address(p)
    conds = []
    if f.numFilterConditions and f.filterCondition:
        sz = ctypes.sizeof(FWPM_FILTER_CONDITION0)
        for i in range(f.numFilterConditions):
            c = FWPM_FILTER_CONDITION0.from_address(f.filterCondition + i * sz)
            conds.append((
                guid_str(c.fieldKey),
                c.matchType,
                copy_value(c.conditionValue),
            ))
    return {
        "id": f.filterId,
        "filterKey": guid_str(f.filterKey),
        "name": f.displayData.name,
        "desc": f.displayData.description,
        "layer": guid_str(f.layerKey),
        "sublayer": guid_str(f.subLayerKey),
        "flags": f.flags,
        "action": f.action.type,
        "providerKey": guid_str(ctypes.cast(f.providerKey, ctypes.POINTER(ctypes.c_char * 16))[0]) if f.providerKey else None,
        "conds": conds,
        "weight": copy_value(f.weight) if f.weight.type != FWP_EMPTY else None,
        "eff_weight": (
            ctypes.c_uint64.from_address(f.effectiveWeight.value.ptr).value
            if f.effectiveWeight.type == FWP_UINT64 and f.effectiveWeight.value.ptr
            else 0
        ),
    }


# ---------------------------------------------------------------------------
# 引擎封装
# ---------------------------------------------------------------------------
class WfpEngine(object):
    def __init__(self):
        self.h = ctypes.c_void_p()

    def open(self):
        hr = FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(self.h))
        if hr != 0:
            u = hr & 0xFFFFFFFF
            if u == 0x80070005:
                raise WfpError(hr, "打开 BFE 引擎被拒绝。请以管理员身份运行本工具。")
            raise WfpError(hr, "打开 WFP 引擎失败 (FwpmEngineOpen0)。")

    def close(self):
        if self.h:
            FwpmEngineClose0(self.h)
            self.h = ctypes.c_void_p()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ---- 通用枚举: 每批在 FwpmFreeMemory0 前完成深拷贝 ----
    @staticmethod
    def _enum(create, destroy, enum_fn, copy_one, engine):
        enum_handle = ctypes.c_void_p()
        check(create(engine, None, ctypes.byref(enum_handle)), "创建枚举句柄")
        result = []
        try:
            while True:
                entries = ctypes.c_void_p()
                count = ctypes.c_uint()
                check(enum_fn(engine, enum_handle, 512,
                              ctypes.byref(entries), ctypes.byref(count)), "枚举对象")
                if count.value == 0:
                    break
                arr = ctypes.cast(entries, ctypes.POINTER(ctypes.c_void_p))
                for i in range(count.value):
                    result.append(copy_one(arr[i]))   # BFE 内存此刻有效
                FwpmFreeMemory0(ctypes.byref(entries))
                if count.value < 512:
                    break
        finally:
            destroy(engine, enum_handle)
        return result

    def enum_filters(self):
        return WfpEngine._enum(FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0,
                               FwpmFilterEnum0, copy_filter, self.h)

    def enum_sublayers(self):
        def copy_sl(p):
            s = FWPM_SUB_LAYER0.from_address(p)
            return {"key": guid_str(s.subLayerKey), "name": s.displayData.name,
                    "weight": s.weight}
        return WfpEngine._enum(FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0,
                               FwpmSubLayerEnum0, copy_sl, self.h)

    def enum_layers(self):
        def copy_l(p):
            l = FWPM_LAYER0.from_address(p)
            return {"key": guid_str(l.layerKey), "name": l.displayData.name,
                    "desc": l.displayData.description}
        return WfpEngine._enum(FwpmLayerCreateEnumHandle0, FwpmLayerDestroyEnumHandle0,
                               FwpmLayerEnum0, copy_l, self.h)

    def get_filter(self, fid):
        p = ctypes.c_void_p()
        hr = FwpmFilterGetById0(self.h, fid, ctypes.byref(p))
        if hr != 0:
            raise WfpError(hr, "未找到 ID 为 %d 的过滤规则 (FwpmFilterGetById0)。" % fid)
        try:
            return copy_filter(p.value)
        finally:
            FwpmFreeMemory0(ctypes.byref(p))

    def ensure_sublayer(self, key, name, weight=0x100):
        """确保持久子层存在; 持久 filter 必须挂在持久子层上"""
        sl = FWPM_SUB_LAYER0()
        guid_set(sl.subLayerKey, key)
        sl.displayData.name = name
        sl.flags = FWPM_SUBLAYER_FLAG_PERSISTENT
        sl.weight = weight
        hr = FwpmSubLayerAdd0(self.h, ctypes.byref(sl), None)
        if (hr & 0xFFFFFFFF) == 0x80320009:
            hr = 0  # FWP_E_ALREADY_EXISTS
        return hr


# ---------------------------------------------------------------------------
# 条件构造 (add 用)
# ---------------------------------------------------------------------------
def parse_protocol(s):
    m = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "any": -1}
    if s.lower() in m:
        return m[s.lower()]
    try:
        n = int(s)
        if 0 <= n <= 255:
            return n
    except ValueError:
        pass
    return -2


def parse_port_list(s):
    """None → [(-1,-1)]; '80' / '80-90' / '80,443' → [(lo,hi), ...]; 非法 → None"""
    if s is None:
        return [(-1, -1)]
    parts = s.split(",")
    if len(parts) > 16:
        return None
    out = []
    for part in parts:
        p = part.strip()
        if "-" in p:
            bits = p.split("-", 1)
            try:
                lo, hi = int(bits[0]), int(bits[1])
            except ValueError:
                return None
            if lo < 1 or hi < lo or hi > 65535:
                return None
            out.append((lo, hi))
        else:
            try:
                v = int(p)
            except ValueError:
                return None
            if v < 1 or v > 65535:
                return None
            out.append((v, v))
    return out


def add_port_cond(conds, keep, field_guid, pr):
    c = FWPM_FILTER_CONDITION0()
    guid_set(c.fieldKey, field_guid)
    lo, hi = pr
    if lo == hi:
        c.matchType = FWP_MATCH_EQUAL
        c.conditionValue.type = FWP_UINT16
        c.conditionValue.value.uint16 = lo
    else:
        nlo, nhi = lo, hi
        if nlo > nhi:
            raise WfpError(None,
                "端口范围 %d-%d 无效 (起大于止)。"
                % (lo, hi))
        r = FWP_RANGE0()
        r.low.type = FWP_UINT16
        r.low.value.uint16 = nlo
        r.high.type = FWP_UINT16
        r.high.value.uint16 = nhi
        keep.append(r)
        c.matchType = FWP_MATCH_RANGE
        c.conditionValue.type = FWP_RANGE_TYPE
        c.conditionValue.value.ptr = ctypes.addressof(r)
    conds.append(c)


def add_ip_cond(conds, keep, field_guid, spec):
    """IP 条件: IPv4 (8 字节 addr+mask, 网络序) / IPv6 (17 字节 addr+prefixLength)"""
    spec = spec.strip()
    if "/" in spec:
        ip_str, mask_str = spec.split("/", 1)
    else:
        ip_str, mask_str = spec, None

    af = socket.AF_INET6 if ":" in ip_str else socket.AF_INET
    try:
        packed = socket.inet_pton(af, ip_str)
    except (OSError, ValueError):
        raise WfpError(None, "无法解析 IP 地址: %s" % ip_str)

    c = FWPM_FILTER_CONDITION0()
    guid_set(c.fieldKey, field_guid)
    c.matchType = FWP_MATCH_EQUAL

    if af == socket.AF_INET:
        if mask_str is None:
            mask = 0xFFFFFFFF
        else:
            try:
                prefix = int(mask_str)
            except ValueError:
                try:
                    # 点分十进制掩码: inet_aton 按字节序返回, 需大端解包成网络字节序数值
                    mask = struct.unpack(">I", socket.inet_aton(mask_str))[0]
                except OSError:
                    raise WfpError(None, "无法解析掩码: %s" % mask_str)
            else:
                if prefix < 0 or prefix > 32:
                    raise WfpError(None, "无效的前缀长度: %s" % mask_str)
                mask = 0 if prefix == 0 else (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        # addr 为网络字节序数值: inet_aton 的 4 字节 (A B C D) 用 >I 解包得 0xABCD 数值
        addr = struct.unpack(">I", socket.inet_aton(ip_str))[0]
        buf = ctypes.create_string_buffer(struct.pack("<I", addr) +
                                          struct.pack("<I", mask), 8)
        c.conditionValue.type = FWP_V4_ADDR_MASK
    else:
        prefix = 128
        if mask_str is not None:
            try:
                prefix = int(mask_str)
            except ValueError:
                raise WfpError(None, "IPv6 掩码请使用前缀长度, 如 2001:db8::/32")
            if prefix < 0 or prefix > 128:
                raise WfpError(None, "无效的前缀长度: %s" % mask_str)
        buf = ctypes.create_string_buffer(packed + bytes([prefix]), 17)
        c.conditionValue.type = FWP_V6_ADDR_MASK

    keep.append(buf)
    c.conditionValue.value.ptr = ctypes.addressof(buf)
    conds.append(c)


# ---------------------------------------------------------------------------
# 显示
# ---------------------------------------------------------------------------
PROTO_NAMES = {1: "ICMP (1)", 6: "TCP (6)", 17: "UDP (17)", 47: "GRE (47)", 58: "ICMPv6 (58)"}

FIELD_NAMES = {
    COND_IP_PROTOCOL: "协议",
    COND_IP_LOCAL_ADDRESS: "本地地址",
    COND_IP_REMOTE_ADDRESS: "远程地址",
    COND_IP_LOCAL_PORT: "本地端口",
    COND_IP_REMOTE_PORT: "远程端口",
    COND_ALE_APP_ID: "应用程序",
    COND_ALE_USER_ID: "用户",
    COND_IPSEC_QM_SA_ID: "IPsec SA ID",
    # ---- SDK fwpmu.h 内置条件字段 (全量补充) ----
    "f6e63dce-1f4b-4c6b-b6ef-1165e71f8ee7": "接口MAC地址",
    "d999e981-7948-4c8e-b742-c84e3b678f8f": "本地MAC地址",
    "408f2ed4-3a70-4b4d-92a6-415ac20e2f12": "远程MAC地址",
    "fd08948d-a219-4d52-bb98-1a5540ee7b4e": "以太网类型",
    "938eab21-3618-4e64-9ca5-2141ebda1ca2": "VLAN ID",
    "7bc43cbf-37ba-45f1-b74a-82ff518eeb10": "二层标志",
    "cc31355c-3073-4ffb-a14f-79415cb1ead1": "本地MAC地址类型",
    "027fedb4-f1c1-4030-b564-ee777fd867ea": "远程MAC地址类型",
    "71bc78fa-f17c-4997-a602-6abb261f351c": "应用包ID",
    "7b795451-f1f6-4d05-b7cb-21779d802336": "源MAC地址",
    "04ea2a93-858c-4027-b613-b43180c7859e": "目的MAC地址",
    "5c1b72e4-299e-4437-a298-bc3f014b3dc2": "源MAC地址类型",
    "ae052932-ef42-4e99-b129-f3b3139e34f7": "目的MAC地址类型",
    "a6afef91-3df4-4730-a214-f5426aebf821": "源端口",
    "ce6def45-60fb-4a7b-a304-af30a117000e": "目的端口",
    "ae96897e-2e94-4bc9-b313-b27ee80e574d": "源IP地址",
    "2d79133b-b390-45c6-8699-acaceaafed33": "目的IP地址",
    "6ec7f6c4-376b-45d7-9e9c-d337cedcd237": "本地地址类型",
    "1ec1b7c9-4eea-4f5e-b9ef-76beaaaf17ee": "目的地址类型",
    "eabe448a-a711-4d64-85b7-3f76b65299c7": "下一跳地址",
    "4cd62a49-59c3-4969-b7f3-bda5d32890a4": "本地接口",
    "618a9b6d-386b-4136-ad6e-b51587cfb1cd": "到达接口",
    "89f990de-e798-4e6d-ab76-7c9558292e6f": "到达接口类型",
    "511166dc-7a8c-4aa7-b533-95ab59fb0340": "到达隧道类型",
    "cc088db3-1792-4a71-b0f9-037d21cd828b": "到达接口索引",
    "ef8a6122-0577-45a7-9aaf-825fbeb4fb95": "下一跳子接口索引",
    "93ae8f5b-7f6f-4719-98c8-14e97429ef04": "下一跳接口",
    "97537c6c-d9a3-4767-a381-e942675cd920": "下一跳接口类型",
    "72b1a111-987b-4720-99dd-c7c576fa2d4c": "下一跳隧道类型",
    "138e6888-7ab8-4d65-9ee8-0591bcf6a494": "下一跳接口索引",
    "46ea1551-2255-492b-8019-aabeee349f40": "原始配置文件ID",
    "ab3033c9-c0e3-4759-937d-5758c65d4ae3": "当前配置文件ID",
    "4ebf7562-9f18-4d06-9941-a7a625744d71": "本地接口配置文件ID",
    "cdfe6aab-c083-4142-8679-c08f95329c61": "到达接口配置文件ID",
    "d7ff9a56-cdaa-472b-84db-d23963c1d1bf": "下一跳接口配置文件ID",
    "11205e8c-11ae-457a-8a44-477026dd764a": "重新授权原因",
    "076dfdbe-c56c-4f72-ae8a-2cfe7e5c8286": "原始ICMP类型",
    "da50d5c8-fa0d-4c89-b032-6e62136d1e96": "物理到达接口",
    "f09bd5ce-5150-48be-b098-c25152fb1f92": "物理下一跳接口",
    "cce68d5e-053b-43a8-9a6f-33384c28e4f6": "接口隔离纪元",
    "daf8cd14-e09e-4c93-a5ae-c5c13b73ffca": "接口类型",
    "77a40437-8779-4868-a261-f5a902f1c0cd": "隧道类型",
    "1076b8a5-6323-4c5e-9810-e8d3fc9e6136": "IP转发接口",
    "4672a468-8a0a-4202-abb4-849e92e66809": "内嵌本地地址类型",
    "77ee4b39-3273-4671-b63b-ab6feb66eeb6": "内嵌远程地址",
    "07784107-a29e-4c7b-9ec7-29c44afafdbc": "内嵌协议",
    "bfca394d-acdb-484e-b8e6-2aff79757345": "内嵌本地端口",
    "cae4d6a1-2968-40ed-a4ce-547160dda88d": "内嵌远程端口",
    "632ce23b-5167-435c-86d7-e903684aa80c": "标志",
    "8784c146-ca97-44d6-9fd1-19fb1840cbf7": "方向",
    "667fd755-d695-434a-8af5-d3835a1259bc": "接口索引",
    "0cd42473-d621-4be3-ae8c-72a348d283e1": "子接口索引",
    "2311334d-c92d-45bf-9496-edf447820e2d": "源接口索引",
    "055edd9d-acd2-4361-8dab-f9525d97662f": "源子接口索引",
    "35cf6522-4139-45ee-a0d5-67b80949d879": "目的接口索引",
    "2b7d4399-d4c7-4738-a2f5-e994b43da388": "目的子接口索引",
    "0e6cd086-e1fb-4212-842f-8a9f993fb3f6": "原始应用程序",
    "f63073b7-0189-4ab0-95a4-6123cbfab862": "远程用户",
    "1aa47f51-7f93-4508-a271-81abb00c9cab": "远程计算机",
    "1c974776-7182-46e9-afd3-b02910e30334": "混杂模式",
    "b482d227-1979-4a98-8044-18bbe6237542": "ALE重新授权原因",
    "46275a9d-c03f-4d77-b784-1c57f4d02753": "ALE NAP上下文",
    "37a57699-5883-4963-92b8-3e704688b0ad": "应用安全属性FQBN",
    "b1277b9a-b781-40fc-9671-e5f1b989f34e": "有效名称",
    "37a57700-5884-4964-92b8-3e704688b0ad": "IPsec安全域ID",
    "35d0ea0e-15ca-492b-900e-97fd46352cce": "IPsec认证NAP上下文",
    "9bf0ee66-06c9-41b9-84da-288cb43af51f": "远程用户令牌",
    "7c9c7d9f-0075-4d35-a0d1-8311c4cf6af1": "RPC接口UUID",
    "eabfd9b7-1262-4a2e-adaa-5f96f6fe326d": "RPC接口版本",
    "238a8a32-3199-467d-871c-272621ab3896": "RPC接口标志",
    "ff2e7b4d-3112-4770-b636-4d24ae3a6af2": "DCOM应用ID",
    "d024de4d-deaa-4317-9c85-e40ef6e140c3": "镜像名称",
    "2717bc74-3a35-4ce7-b7ef-c838fabdec45": "RPC协议",
    "daba74ab-0d67-43e7-986e-75b84f82f594": "RPC认证类型",
    "e5a0aed5-59ac-46ea-be05-a5f05ecf446e": "RPC认证级别",
    "0d306ef0-e974-4f74-b5c7-591b0da7d562": "加密算法",
    "4772183b-ccf8-4aeb-bce1-c6c6161c8fe4": "密钥长度",
    "1bd0741d-e3df-4e24-8634-762046eef6eb": "管道",
    "e31180a8-bbbd-4d14-a65e-7157b06233bb": "RPC进程UUID",
    "dccea0b9-0886-4360-9c6a-ab043a24fba9": "RPC端点值",
    "218b814a-0a39-49b8-8e71-c20c39c7dd2e": "RPC端点标志",
    "c228fc1e-403a-4478-be05-c9baa4c05ace": "客户端令牌",
    "b605a225-c3b3-48c7-9833-7aefa9527546": "RPC服务器名",
    "8090f645-9ad5-4e3b-9f9f-8023ca097909": "RPC服务器端口",
    "40953fe2-8565-4759-8488-1771b4b4b5db": "RPC代理认证类型",
    "a3ec00c7-05f4-4df7-91f2-5f60d91ff443": "客户端证书密钥长度",
    "c491ad5e-f882-4283-b916-436b103ff4ad": "客户端证书OID",
    "206e9996-490e-40cf-b831-b38641eb6fcb": "网络事件类型",
    "9b539082-eb90-4186-a6cc-de5b63235016": "对等名称",
    "f68166fd-0682-4c89-b8f5-86436c7ef9b7": "远程ID",
    "eb458cd5-da7b-4ef9-8d43-7b0a840332f2": "认证类型",
    "ff0f5f49-0ceb-481b-8638-1479791f3f2c": "密钥管理类型",
    "feef4582-ef8f-4f7b-858b-9077d122de47": "密钥管理模式",
    "ad37dee3-722f-45cc-a4e3-068048124452": "IPsec策略Key",
    "f64fc6d1-f9cb-43d2-8a5f-e13bc894f265": "IPsec快速模式",
    "dc04843c-79e6-4e44-a025-65b9bb0f9f94": "vSwitch租户网络ID",
    "c4a414ba-437b-4de6-9946-d99c1b95b312": "vSwitch ID",
    "11d48b4b-e77a-40b4-9155-392c906c2608": "vSwitch网络类型",
    "db7bb42b-2dac-4cd4-a59a-e0bdce1e6834": "NDIS端口",
}

# 配置文件 ID 字段 (值解码: 1=域 2=专用 4=公用)
PROFILE_ID_FIELDS = frozenset([
    "46ea1551-2255-492b-8019-aabeee349f40",
    "ab3033c9-c0e3-4759-937d-5758c65d4ae3",
    "4ebf7562-9f18-4d06-9941-a7a625744d71",
    "cdfe6aab-c083-4142-8679-c08f95329c61",
    "d7ff9a56-cdaa-472b-84db-d23963c1d1bf",
])


def profile_name(v):
    s = []
    if v & 1:
        s.append("域")
    if v & 2:
        s.append("专用")
    if v & 4:
        s.append("公用")
    return ", ".join(s) if s else "未知"

MATCH_NAMES = {
    FWP_MATCH_EQUAL: "=", 1: ">", 2: "<", 3: ">=", 4: "<=",
    FWP_MATCH_RANGE: "在范围内",
    6: "标志全为1", 7: "标志任一为1", 8: "标志全为0",
    9: "等于(忽略大小写)", 10: "!=", 11: "前缀",
}

TYPE_NAMES = {
    FWP_UINT8: "UINT8", FWP_UINT16: "UINT16", FWP_UINT32: "UINT32",
    FWP_INT8: "INT8", FWP_INT16: "INT16", FWP_INT32: "INT32",
    FWP_UINT64: "UINT64", FWP_INT64: "INT64",
    FWP_FLOAT: "FLOAT", FWP_DOUBLE: "DOUBLE",
    FWP_BYTE_ARRAY16_TYPE: "ARRAY16", FWP_BYTE_BLOB_TYPE: "BLOB",
    FWP_SECURITY_DESCRIPTOR_TYPE: "SD", FWP_SID: "SID",
    FWP_UNICODE_STRING_TYPE: "UNISTR",
    FWP_V4_ADDR_MASK: "V4MASK", FWP_V6_ADDR_MASK: "V6MASK",
    FWP_RANGE_TYPE: "RANGE", FWP_EMPTY: "EMPTY",
}


def ip4(a):
    """网络字节序数值 (0xAABBCCDD) → 点分 IP"""
    return "%d.%d.%d.%d" % ((a >> 24) & 0xFF, (a >> 16) & 0xFF,
                            (a >> 8) & 0xFF, a & 0xFF)


def render_value(val, is_port=False, is_addr=False):
    if val is None:
        return "<无条件>"
    t, o = val
    if t == FWP_UINT8:
        return PROTO_NAMES.get(o, str(o))
    if t == FWP_UINT16:
        return str(o)
    if t == FWP_UINT32:
        return ip4(o) if is_addr else str(o)
    if t in (FWP_INT32, FWP_UINT64, FWP_INT64,
             FWP_INT8, FWP_INT16, FWP_FLOAT, FWP_DOUBLE):
        return str(o)
    if t == FWP_BYTE_ARRAY16_TYPE:
        return socket.inet_ntop(socket.AF_INET6, o)
    if t == FWP_BYTE_BLOB_TYPE:
        if not o:
            return "<空>"
        if len(o) % 2 == 0:
            try:
                s = o.decode("utf-16-le")
                if all(ch == "\0" or ch.isprintable() or ch in " \t" for ch in s):
                    return s.rstrip("\0")
            except UnicodeDecodeError:
                pass
        return "<数据 %d 字节>" % len(o)
    if t == FWP_SECURITY_DESCRIPTOR_TYPE:
        # 将 SD 字节转换为 SDDL 字符串
        if not o or len(o) == 0:
            return "<空>"
        import ctypes
        sd_ptr = ctypes.create_string_buffer(o)
        sddl = ctypes.c_wchar_p()
        if _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd_ptr, 1, 7, ctypes.byref(sddl), ctypes.byref(ctypes.c_uint(0))):
            s = sddl.value or ""
            _kernel32.LocalFree(ctypes.cast(sddl, ctypes.c_void_p))
            return s
        return "<安全描述符 %d 字节>" % len(o)
    if t == FWP_SID:
        return o if o else "<SID>"
    if t == FWP_UNICODE_STRING_TYPE:
        return o or ""
    if t == FWP_V4_ADDR_MASK:
        addr, mask = o
        s = socket.inet_ntoa(struct.pack(">I", addr))
        pfx = popcount(mask)
        return s if pfx == 32 else "%s/%d" % (s, pfx)
    if t == FWP_V6_ADDR_MASK:
        raw, pfx = o
        s = socket.inet_ntop(socket.AF_INET6, raw)
        return s if pfx == 128 else "%s/%d" % (s, pfx)
    if t == FWP_RANGE_TYPE:
        (lo_t, lo), (hi_t, hi) = o
        if is_addr and not is_port and lo_t == FWP_UINT32 and hi_t == FWP_UINT32 and lo <= hi:
            diff = hi - lo + 1
            if diff & (diff - 1) == 0 and (lo & (diff - 1)) == 0:
                pfx = 32
                d = diff
                while d > 1:
                    d >>= 1
                    pfx -= 1
                return "%s/%d" % (ip4(lo), pfx)
            return "%s ~ %s" % (ip4(lo), ip4(hi))
        return "%s ~ %s" % (render_value((lo_t, lo), is_port, is_addr),
                            render_value((hi_t, hi), is_port, is_addr))
    if t == FWP_EMPTY:
        return "<无条件>"
    return "(类型 %d)" % t


def action_name(action, long_form=False):
    if action == FWP_ACTION_BLOCK:
        return "BLOCK (阻断)" if long_form else "BLOCK"
    if action == FWP_ACTION_PERMIT:
        return "PERMIT (放行)" if long_form else "PERMIT"
    if action & 0x00004000:
        return "CALLOUT"
    return "0x%X" % action


def flags_str(flags):
    s = ""
    if flags & FWPM_FILTER_FLAG_PERSISTENT:
        s += "P"
    if flags & FWPM_FILTER_FLAG_BOOTTIME:
        s += "B"
    if flags & FWPM_FILTER_FLAG_DISABLED:
        s += "D"
    if flags & FWPM_FILTER_FLAG_INDEXED:
        s += "I"
    return s or "-"


# ---------------------------------------------------------------------------
# 命令实现
# ---------------------------------------------------------------------------
def cmd_add(argv):
    name = "wfpctl rule"
    desc = ""
    layer_str = "connect-v4"
    sublayer_str = None
    action = "permit"   # 默认放行; 阻断需显式 --action block
    protocol = -1
    lport_str = rport_str = None
    lip_list = rip_list = None
    app = None
    boottime = False
    volatile = False
    weight = -1

    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--name" and i + 1 < len(argv):
            name = argv[i + 1]; i += 1
        elif a == "--desc" and i + 1 < len(argv):
            desc = argv[i + 1]; i += 1
        elif a == "--layer" and i + 1 < len(argv):
            layer_str = argv[i + 1]; i += 1
        elif a == "--sublayer" and i + 1 < len(argv):
            sublayer_str = argv[i + 1]; i += 1
        elif a == "--action" and i + 1 < len(argv):
            action = argv[i + 1].lower(); i += 1
        elif a == "--protocol" and i + 1 < len(argv):
            protocol = parse_protocol(argv[i + 1]); i += 1
        elif a == "--lport" and i + 1 < len(argv):
            lport_str = argv[i + 1]; i += 1
        elif a == "--rport" and i + 1 < len(argv):
            rport_str = argv[i + 1]; i += 1
        elif a == "--lip" and i + 1 < len(argv):
            if lip_list is None:
                lip_list = []
            lip_list.append(argv[i + 1]); i += 1
        elif a == "--rip" and i + 1 < len(argv):
            if rip_list is None:
                rip_list = []
            rip_list.append(argv[i + 1]); i += 1
        elif a == "--app" and i + 1 < len(argv):
            app = argv[i + 1]; i += 1
        elif a == "--boottime":
            boottime = True
        elif a == "--volatile":
            volatile = True
        elif a == "--weight" and i + 1 < len(argv):
            try:
                weight = int(argv[i + 1])
            except ValueError:
                weight = -2
            i += 1
            if weight < 0 or weight > 15:
                print("add: --weight 须为 0-15 (15 最高优先, 同子层内先评估)。缺省则由 BFE 自动分配。")
                return 1
        else:
            print("add: 无法识别的参数 " + a)
            return 1
        i += 1

    if protocol == -2:
        print("add: 无效的协议。")
        return 1

    layer = resolve_layer(layer_str)
    if layer is None:
        print('add: 无法识别的层 "%s"。可用别名:' % layer_str)
        for alias, _, d in LAYER_ALIASES:
            print("  %-11s  %s" % (alias, d))
        return 1

    if sublayer_str == "default" or sublayer_str is None:
        sublayer = WFPCTL_SUBLAYER
    else:
        sublayer = resolve_layer(sublayer_str)
        if sublayer is None:
            print("add: 无效的子层 GUID: " + sublayer_str)
            return 1

    if action == "block":
        action_type = FWP_ACTION_BLOCK
    elif action in ("permit", "allow"):
        action_type = FWP_ACTION_PERMIT
    else:
        print("add: --action 仅支持 block 或 permit。")
        return 1

    lports = parse_port_list(lport_str)
    rports = parse_port_list(rport_str)
    if lports is None or rports is None:
        print("add: 无效的端口, 应为 80 / 80-90 / 80,443 形式 (1-65535)。")
        return 1
    total = len(lports) * len(rports)
    if total > 64:
        print("add: 端口组合过多 (%d 条), 请分批添加。" % total)
        return 1

    app_blob = None
    if app is not None:
        app_blob = ctypes.c_void_p()
        rc = FwpmGetAppIdFromFileName0(app, ctypes.byref(app_blob))
        if rc != 0:
            print('add: 获取应用程序 ID 失败 (0x%08X)。请确认文件路径存在。' % rc)
            return 1

    flags = 0
    # 注意: BOOTTIME 自身已隐含持久化, 与 PERSISTENT 组合会被 BFE 以
    # FWP_E_INVALID_FLAGS (0x8032001E) 拒绝
    if boottime:
        flags = FWPM_FILTER_FLAG_BOOTTIME
    elif not volatile:
        flags = FWPM_FILTER_FLAG_PERSISTENT

    try:
        with WfpEngine() as eng:
            check(FwpmTransactionBegin0(eng.h, 0), "开始事务")
            ok = False
            added = []
            keep = []          # ctypes 缓冲保活, 提交前不得释放
            try:
                check(eng.ensure_sublayer(sublayer, TOOL_SUBLAYER_NAME), "创建子层")

                seq = 0
                for (llo, lhi) in lports:
                    for (rlo, rhi) in rports:
                        seq += 1
                        fname = "%s #%d" % (name, seq) if total > 1 else name

                        conds = []
                        if protocol >= 0:
                            c = FWPM_FILTER_CONDITION0()
                            guid_set(c.fieldKey, COND_IP_PROTOCOL)
                            c.matchType = FWP_MATCH_EQUAL
                            c.conditionValue.type = FWP_UINT8
                            c.conditionValue.value.uint8 = protocol
                            conds.append(c)
                        if lip_list:
                            for s in lip_list:
                                add_ip_cond(conds, keep, COND_IP_LOCAL_ADDRESS, s)
                        if rip_list:
                            for s in rip_list:
                                add_ip_cond(conds, keep, COND_IP_REMOTE_ADDRESS, s)
                        if llo >= 0:
                            add_port_cond(conds, keep, COND_IP_LOCAL_PORT, (llo, lhi))
                        if rlo >= 0:
                            add_port_cond(conds, keep, COND_IP_REMOTE_PORT, (rlo, rhi))
                        if app_blob and app_blob.value:
                            c = FWPM_FILTER_CONDITION0()
                            guid_set(c.fieldKey, COND_ALE_APP_ID)
                            c.matchType = FWP_MATCH_EQUAL
                            c.conditionValue.type = FWP_BYTE_BLOB_TYPE
                            c.conditionValue.value.ptr = app_blob.value
                            conds.append(c)

                        arr = (FWPM_FILTER_CONDITION0 * len(conds))()
                        for k, c in enumerate(conds):
                            arr[k].fieldKey = c.fieldKey
                            arr[k].matchType = c.matchType
                            arr[k].conditionValue = c.conditionValue
                        keep.append(arr)

                        f = FWPM_FILTER0()
                        guid_set(f.layerKey, layer)
                        guid_set(f.subLayerKey, sublayer)
                        f.flags = flags
                        if weight >= 0:
                            f.weight.type = FWP_UINT8
                            f.weight.value.uint8 = weight
                        f.action.type = action_type
                        f.displayData.name = fname
                        f.displayData.description = desc
                        f.numFilterConditions = len(conds)
                        f.filterCondition = ctypes.addressof(arr) if conds else None

                        fid = ctypes.c_uint64()
                        check(FwpmFilterAdd0(eng.h, ctypes.byref(f), None,
                                            ctypes.byref(fid)),
                              "添加规则 #%d (FwpmFilterAdd0)" % seq)
                        added.append(fid.value)

                check(FwpmTransactionCommit0(eng.h), "提交事务")
                ok = True
            finally:
                if not ok:
                    FwpmTransactionAbort0(eng.h)
                del keep[:]
                if app_blob and app_blob.value:
                    FwpmFreeMemory0(ctypes.byref(app_blob))

            for fid in added:
                print("已添加规则, ID = %d  名称 = %s" % (fid, name))
            if boottime:
                print("提示: 该规则为启动时间规则 (BFE 未启动时即生效)。")
            print('提示: 使用 "wfpctl.py list" 查看, "wfpctl.py del <ID>" 删除。')
            return 0
    except WfpError as e:
        print("错误: " + e.msg)
        if e.hr:
            print("(HRESULT = %s)" % hr_msg(e.hr))
        return 1


def cmd_update(argv):
    """修改规则 (事务内删旧+建新; 未指定的参数保持原值; any 清除条件)"""
    if not argv:
        print("用法: wfpctl.py update <规则ID> [参数]。未指定的保持原值; any 清除条件。")
        return 1
    try:
        fid = int(argv[0])
    except ValueError:
        print("update: 无效的规则 ID: " + argv[0])
        return 1

    # 用户覆盖参数 (None/-2 = 未指定)
    name = desc = layer_str = sublayer_str = None
    action = None
    protocol = -2
    lip_list = rip_list = None
    has_lip = has_rip = has_lport = has_rport = has_app = False
    app = None
    weight_set = -1          # -1=未指定 0=auto 1=指定
    weight = 0
    boottime = -1
    volatile = -1

    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--name" and i + 1 < len(argv): name = argv[i + 1]; i += 1
        elif a == "--desc" and i + 1 < len(argv): desc = argv[i + 1]; i += 1
        elif a == "--action" and i + 1 < len(argv):
            act = argv[i + 1].lower(); i += 1
            if act == "block": action = "block"
            elif act in ("permit", "allow"): action = "permit"
            else: print("update: --action 仅支持 block 或 permit。"); return 1
        elif a == "--protocol" and i + 1 < len(argv):
            protocol = parse_protocol(argv[i + 1]); i += 1
            if protocol == -2: print("update: 无效的协议。"); return 1
        elif a == "--lip" and i + 1 < len(argv):
            has_lip = True; v = argv[i + 1]; i += 1
            if v.lower() == "any": lip_list = None
            else:
                if lip_list is None: lip_list = []
                lip_list.append(v)
        elif a == "--rip" and i + 1 < len(argv):
            has_rip = True; v = argv[i + 1]; i += 1
            if v.lower() == "any": rip_list = None
            else:
                if rip_list is None: rip_list = []
                rip_list.append(v)
        elif a == "--lport" and i + 1 < len(argv):
            has_lport = True; v = argv[i + 1]
            lport_str = None if v.lower() == "any" else v; i += 1
        elif a == "--rport" and i + 1 < len(argv):
            has_rport = True; v = argv[i + 1]
            rport_str = None if v.lower() == "any" else v; i += 1
        elif a == "--app" and i + 1 < len(argv):
            has_app = True; v = argv[i + 1]
            app = None if v.lower() == "any" else v; i += 1
        elif a == "--weight" and i + 1 < len(argv):
            v = argv[i + 1]; i += 1
            if v.lower() == "auto": weight_set = 0
            else:
                try: weight = int(v)
                except ValueError: weight = -2
                if weight < 0 or weight > 15:
                    print("update: --weight 须为 0-15 或 auto。"); return 1
                weight_set = 1
        elif a == "--boottime": boottime = 1
        elif a == "--volatile": volatile = 1
        elif a == "--persistent": volatile = 0
        elif a == "--layer" and i + 1 < len(argv): layer_str = argv[i + 1]; i += 1
        elif a == "--sublayer" and i + 1 < len(argv): sublayer_str = argv[i + 1]; i += 1
        else: print("update: 无法识别的参数 " + a); return 1
        i += 1

    if boottime == 1 and volatile == 1:
        print("update: --boottime 与 --volatile 互斥。"); return 1

    user_app_blob = None
    try:
        with WfpEngine() as eng:
            try:
                f = eng.get_filter(fid)
            except WfpError:
                print("update: 未找到 ID 为 %d 的规则。" % fid)
                return 1
            if f["action"] != FWP_ACTION_BLOCK and f["action"] != FWP_ACTION_PERMIT:
                print("update: 仅支持修改 BLOCK/PERMIT 动作的规则。")
                return 1

            # ---- 提取基值 ----
            b_name = f["name"] or "wfpctl rule"
            b_desc = f["desc"] or ""
            b_action_block = (f["action"] == FWP_ACTION_BLOCK)
            b_layer = f["layer"]
            b_sublayer = f["sublayer"]
            b_boottime = bool(f["flags"] & FWPM_FILTER_FLAG_BOOTTIME)
            b_volatile = not b_boottime and not (f["flags"] & FWPM_FILTER_FLAG_PERSISTENT)
            bw = f["weight"]
            b_weight_set = bw is not None and bw[0] == FWP_UINT8
            b_weight_val = bw[1] if b_weight_set else 0
            b_proto = -1
            b_lip = b_rip = b_lport = b_rport = None
            b_app_bytes = None
            b_has_app = False
            for (fg, mt, val) in f["conds"]:
                if fg == COND_IP_PROTOCOL:
                    if val[0] == FWP_UINT8: b_proto = val[1]
                elif fg == COND_IP_LOCAL_ADDRESS:
                    b_lip = render_value(val, False, True)
                elif fg == COND_IP_REMOTE_ADDRESS:
                    b_rip = render_value(val, False, True)
                elif fg == COND_IP_LOCAL_PORT:
                    b_lport = render_value(val, True)
                elif fg == COND_IP_REMOTE_PORT:
                    b_rport = render_value(val, True)
                elif fg == COND_ALE_APP_ID:
                    if val[0] == FWP_BYTE_BLOB_TYPE and val[1]:
                        b_app_bytes = val[1]
                        b_has_app = True
                else:
                    print("update: 该规则含本工具无法编辑的条件 (%s), 请删除后重新添加。" %
                          FIELD_NAMES.get(fg, "{%s}" % fg))
                    return 1

            # ---- 合成 (用户覆盖 > 旧值) ----
            F_name = name if name is not None else b_name
            F_desc = desc if desc is not None else b_desc
            F_action_block = b_action_block if action is None else (action == "block")
            F_proto = b_proto if protocol == -2 else protocol
            if layer_str is not None:
                F_layer = resolve_layer(layer_str)
                if F_layer is None:
                    print('update: 无法识别的层 "%s"。' % layer_str)
                    return 1
            else:
                F_layer = b_layer
            if sublayer_str is not None:
                if sublayer_str == "default":
                    F_sublayer = WFPCTL_SUBLAYER
                else:
                    F_sublayer = resolve_layer(sublayer_str)
                    if F_sublayer is None:
                        print("update: 无效的子层 GUID: " + sublayer_str)
                        return 1
            else:
                F_sublayer = b_sublayer
            F_boottime = b_boottime if boottime == -1 else (boottime == 1)
            F_volatile = b_volatile if volatile == -1 else (volatile == 1)
            if weight_set == -1:
                F_weight_set = b_weight_set
                F_weight = b_weight_val
            else:
                F_weight_set = (weight_set == 1)
                F_weight = weight

            # app
            if has_app:
                if app is not None:
                    user_app_blob = ctypes.c_void_p()
                    rc = FwpmGetAppIdFromFileName0(app, ctypes.byref(user_app_blob))
                    if rc != 0:
                        print('update: 获取应用程序 ID 失败 (0x%08X)。请确认文件路径存在。' % rc)
                        return 1
                    F_has_app = True
                else:
                    F_has_app = False
            elif b_has_app:
                F_has_app = True
            else:
                F_has_app = False

            # lip/rip (支持多个)
            if has_lip:
                F_has_lip = lip_list is not None and len(lip_list) > 0; F_lip = lip_list
            else:
                F_has_lip = b_lip is not None; F_lip = [b_lip] if b_lip else None
            if has_rip:
                F_has_rip = rip_list is not None and len(rip_list) > 0; F_rip = rip_list
            else:
                F_has_rip = b_rip is not None; F_rip = [b_rip] if b_rip else None

            # lport/rport
            F_lport = F_rport = None
            F_has_lport = F_has_rport = False
            if has_lport:
                if lport_str is not None:
                    pl = parse_port_list(lport_str)
                    if pl is None or len(pl) != 1:
                        print("update: 每次只修改一条规则, --lport 仅接受单端口或单范围 (如 80 / 80-90)。")
                        return 1
                    F_lport = pl[0]; F_has_lport = True
            elif b_lport is not None:
                pl = parse_port_list(b_lport)
                if pl is None or len(pl) != 1:
                    print("update: 原规则的端口条件无法解析。")
                    return 1
                F_lport = pl[0]; F_has_lport = True
            if has_rport:
                if rport_str is not None:
                    pl = parse_port_list(rport_str)
                    if pl is None or len(pl) != 1:
                        print("update: 每次只修改一条规则, --rport 仅接受单端口或单范围 (如 80 / 80-90)。")
                        return 1
                    F_rport = pl[0]; F_has_rport = True
            elif b_rport is not None:
                pl = parse_port_list(b_rport)
                if pl is None or len(pl) != 1:
                    print("update: 原规则的端口条件无法解析。")
                    return 1
                F_rport = pl[0]; F_has_rport = True

            # ---- 构造条件 ----
            keep = []
            conds = []
            if F_proto >= 0:
                c = FWPM_FILTER_CONDITION0()
                guid_set(c.fieldKey, COND_IP_PROTOCOL)
                c.matchType = FWP_MATCH_EQUAL
                c.conditionValue.type = FWP_UINT8
                c.conditionValue.value.uint8 = F_proto
                conds.append(c)
            if F_has_rip:
                for s in F_rip:
                    add_ip_cond(conds, keep, COND_IP_REMOTE_ADDRESS, s)
            if F_has_lip:
                for s in F_lip:
                    add_ip_cond(conds, keep, COND_IP_LOCAL_ADDRESS, s)
            if F_has_lport:
                add_port_cond(conds, keep, COND_IP_LOCAL_PORT, F_lport)
            if F_has_rport:
                add_port_cond(conds, keep, COND_IP_REMOTE_PORT, F_rport)
            if F_has_app:
                c = FWPM_FILTER_CONDITION0()
                guid_set(c.fieldKey, COND_ALE_APP_ID)
                c.matchType = FWP_MATCH_EQUAL
                c.conditionValue.type = FWP_BYTE_BLOB_TYPE
                if has_app and app is not None and user_app_blob and user_app_blob.value:
                    c.conditionValue.value.ptr = user_app_blob.value
                else:
                    bd = ctypes.create_string_buffer(b_app_bytes)
                    bs = FWP_BYTE_BLOB()
                    bs.size = len(b_app_bytes)
                    bs.data = ctypes.addressof(bd)
                    keep.append(bd)
                    keep.append(bs)
                    c.conditionValue.value.ptr = ctypes.addressof(bs)
                conds.append(c)

            arr = (FWPM_FILTER_CONDITION0 * len(conds))()
            for k, c in enumerate(conds):
                arr[k].fieldKey = c.fieldKey
                arr[k].matchType = c.matchType
                arr[k].conditionValue = c.conditionValue
            keep.append(arr)

            flags = 0
            if F_boottime:
                flags = FWPM_FILTER_FLAG_BOOTTIME
            elif not F_volatile:
                flags = FWPM_FILTER_FLAG_PERSISTENT

            fnew = FWPM_FILTER0()
            guid_set(fnew.layerKey, F_layer)
            guid_set(fnew.subLayerKey, F_sublayer)
            fnew.flags = flags
            if F_weight_set:
                fnew.weight.type = FWP_UINT8
                fnew.weight.value.uint8 = F_weight
            fnew.action.type = FWP_ACTION_BLOCK if F_action_block else FWP_ACTION_PERMIT
            fnew.displayData.name = F_name
            fnew.displayData.description = F_desc
            fnew.numFilterConditions = len(conds)
            fnew.filterCondition = ctypes.addressof(arr) if conds else None

            # ---- 事务: 删旧 + 建新 ----
            check(FwpmTransactionBegin0(eng.h, 0), "开始事务")
            ok = False
            new_id = 0
            try:
                hr = FwpmFilterDeleteById0(eng.h, fid)
                if hr != 0:
                    raise WfpError(hr, "删除旧规则 %d 失败: %s" % (fid, hr_msg(hr)))
                fid_out = ctypes.c_uint64()
                check(FwpmFilterAdd0(eng.h, ctypes.byref(fnew), None,
                                     ctypes.byref(fid_out)), "重建规则 (FwpmFilterAdd0)")
                new_id = fid_out.value
                check(FwpmTransactionCommit0(eng.h), "提交事务")
                ok = True
            finally:
                if not ok:
                    FwpmTransactionAbort0(eng.h)
                del keep[:]

            print("已修改规则: ID %d → %d  名称 = %s" % (fid, new_id, F_name))
            return 0
    except WfpError as e:
        print("错误: " + e.msg)
        if e.hr:
            print("(HRESULT = %s)" % hr_msg(e.hr))
        return 1
    finally:
        if user_app_blob and user_app_blob.value:
            FwpmFreeMemory0(ctypes.byref(user_app_blob))


def cmd_del(argv):
    if len(argv) == 2 and argv[0] == "--name":
        with WfpEngine() as eng:
            matched = [f["id"] for f in eng.enum_filters() if f["name"] == argv[1]]
            if not matched:
                print('del: 没有找到名称为 "%s" 的规则。' % argv[1])
                return 1
            fail = 0
            for fid in matched:
                hr = FwpmFilterDeleteById0(eng.h, fid)
                if hr != 0:
                    fail += 1
                    print("del: 删除 ID %d 失败 (%s)" % (fid, hr_msg(hr)))
                else:
                    print("已删除规则 ID = %d" % fid)
            return 0 if fail == 0 else 1

    if len(argv) != 1:
        print("用法: wfpctl.py del <规则ID>   或   wfpctl.py del --name <规则名称>")
        return 1
    try:
        fid = int(argv[0])
    except ValueError:
        print("del: 规则 ID 必须是数字。")
        return 1
    with WfpEngine() as eng:
        hr = FwpmFilterDeleteById0(eng.h, fid)
        if hr != 0:
            if (hr & 0xFFFFFFFF) == 0x80320003:
                print("del: 未找到 ID 为 %d 的规则。" % fid)
            else:
                print("错误: 删除规则 %d 失败 (FwpmFilterDeleteById0): %s" % (fid, hr_msg(hr)))
            return 1
        print("已删除规则 ID = %d" % fid)
        return 0


def cmd_list(argv):
    show_all = False
    layer_filter = None
    sublayer_filter = None
    has_sublayer_filter = False
    sublayer_name = None        # 按名称匹配时暂存, 引擎打开后解析
    sublayer_set = []
    name_filter = None
    action_filter = 0          # 0=不过滤 1=BLOCK 2=PERMIT
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--all":
            show_all = True
        elif a == "--name" and i + 1 < len(argv):
            name_filter = argv[i + 1]; i += 1
        elif a == "--action" and i + 1 < len(argv):
            act = argv[i + 1].lower(); i += 1
            if act == "block": action_filter = 1
            elif act in ("permit", "allow"): action_filter = 2
            else: print("list: --action 仅支持 block 或 permit。"); return 1
        elif a == "--layer" and i + 1 < len(argv):
            layer_filter = resolve_layer(argv[i + 1]); i += 1
            if layer_filter is None:
                print("list: 无法识别的层: " + argv[i])
                return 1
        elif a == "--sublayer" and i + 1 < len(argv):
            v = argv[i + 1]; i += 1
            if v == "default":
                sublayer_filter = WFPCTL_SUBLAYER
            else:
                sublayer_filter = resolve_layer(v)
                if sublayer_filter is None:
                    if not v:
                        print("list: --sublayer 需要子层 GUID、名称或 default。")
                        return 1
                    sublayer_name = v   # 不是 GUID → 视为名称, 引擎打开后枚举匹配
            has_sublayer_filter = True
        else:
            print("list: 无法识别的参数 " + a)
            return 1
        i += 1

    with WfpEngine() as eng:
        # --sublayer 传的是名称时: 枚举子层做大小写不敏感子串匹配
        if sublayer_name:
            sublayer_set = [s["key"] for s in eng.enum_sublayers()
                           if s["name"] and sublayer_name.lower() in s["name"].lower()]
            if not sublayer_set:
                print('list: 未找到名称含 "%s" 的子层。可用 "wfpctl.py sublayers" 查看全部子层及其 GUID。'
                      % sublayer_name)
                return 1

        filters = eng.enum_filters()
        if len(sublayer_set) > 1:
            print('按子层名称 "%s" 匹配到 %d 个子层:' % (sublayer_name, len(sublayer_set)))
        print()
        print("ID".ljust(12) + "动作".ljust(10) + "层".ljust(16) + "标志".ljust(8) + "名称")
        print("-" * 78)
        shown = 0
        for f in filters:
            if has_sublayer_filter:
                if sublayer_set:
                    if f["sublayer"] not in sublayer_set:
                        continue
                elif f["sublayer"] != sublayer_filter:
                    continue
            elif not show_all and f["sublayer"] != WFPCTL_SUBLAYER:
                continue
            if layer_filter and f["layer"] != layer_filter:
                continue
            if action_filter == 1 and f["action"] != FWP_ACTION_BLOCK:
                continue
            if action_filter == 2 and f["action"] != FWP_ACTION_PERMIT:
                continue
            if name_filter:
                nm = (f["name"] or "").lower()
                ds = (f["desc"] or "").lower()
                if name_filter.lower() not in nm and name_filter.lower() not in ds:
                    continue
            shown += 1
            lname = layer_alias_of(f["layer"]) or (f["layer"][:13] + "..")
            print(str(f["id"]).ljust(12) + action_name(f["action"]).ljust(10) +
                  lname.ljust(16) + flags_str(f["flags"]).ljust(8) +
                  (f["name"] or "<无名>"))
        print("-" * 78)
        if show_all or name_filter or action_filter or has_sublayer_filter:
            print("共 %d 条规则 (系统全部), 匹配显示 %d 条" % (len(filters), shown))
        else:
            print("共 %d 条规则 (系统全部), 本工具创建 %d 条。加 --all 查看系统全部规则"
                  % (len(filters), shown))
    return 0


def cmd_show(argv):
    if len(argv) != 1:
        print("用法: wfpctl.py show <规则ID>")
        return 1
    try:
        fid = int(argv[0])
    except ValueError:
        print("show: 规则 ID 必须是数字 (可先用 list 查看)。")
        return 1
    with WfpEngine() as eng:
        f = eng.get_filter(fid)
        layer_names = {l["key"]: l["name"] for l in eng.enum_layers() if l["name"]}
        sub_names = {s["key"]: s["name"] for s in eng.enum_sublayers() if s["name"]}

        alias = layer_alias_of(f["layer"])
        print()
        print("规则 ID        : %d" % f["id"])
        print("规则 Key       : {%s}" % f["filterKey"])
        print("名称           : %s" % (f["name"] or ""))
        print("描述           : %s" % (f["desc"] or ""))
        if f.get("providerKey"):
            print("提供者         : {%s}" % f["providerKey"])
        line = "层             : {%s}" % f["layer"]
        if alias:
            line += "  别名 " + alias
        bfe_name = layer_names.get(f["layer"])
        if bfe_name:
            line += "  (%s)" % bfe_name
        print(line)
        sub_name = sub_names.get(f["sublayer"])
        print("子层           : {%s}%s" % (f["sublayer"],
              "  (%s)" % sub_name if sub_name else ""))
        print("标志           : 0x%X%s%s%s%s" % (f["flags"],
              "  [持久]" if f["flags"] & FWPM_FILTER_FLAG_PERSISTENT else "",
              "  [启动时]" if f["flags"] & FWPM_FILTER_FLAG_BOOTTIME else "",
              "  [已禁用]" if f["flags"] & FWPM_FILTER_FLAG_DISABLED else "",
              "  [已索引]" if f["flags"] & 0x40 else ""))
        if f["flags"] & FWPM_FILTER_FLAG_BOOTTIME:
            persist = "是 (启动时, BFE 启动阶段即生效, 重启后仍在)"
        elif f["flags"] & FWPM_FILTER_FLAG_PERSISTENT:
            persist = "是 (重启后仍生效)"
        elif f["sublayer"] == WFPCTL_SUBLAYER:
            persist = "否 (临时规则, BFE 服务重启后消失)"
        else:
            persist = "否 (非持久; 但系统/外部服务规则, 如 Windows 防火墙规则, 其服务启动时自动重建)"
        print("持久化         : %s" % persist)
        print("动作           : %s" % action_name(f["action"], long_form=True))
        wstr = render_value(f["weight"]) if f["weight"] else "自动"
        eff = f["eff_weight"]
        print("权重           : %s%s" % (wstr,
              "  (生效权重 0x%016X, 同子层内值大者优先评估)" % eff if eff else ""))
        print("匹配条件       : %d 个%s" % (len(f["conds"]),
              " (匹配全部流量)" if not f["conds"] else ""))
        for idx, (fg, mt, val) in enumerate(f["conds"]):
            fname = FIELD_NAMES.get(fg, "{%s}" % fg)
            is_port = fg in (COND_IP_LOCAL_PORT, COND_IP_REMOTE_PORT)
            is_addr = fg in (COND_IP_LOCAL_ADDRESS, COND_IP_REMOTE_ADDRESS)
            tname = TYPE_NAMES.get(val[0], "0x%X" % val[0]) if val else ""
            if fg in PROFILE_ID_FIELDS and val and val[0] == FWP_UINT32:
                vstr = "%d (%s)" % (val[1], profile_name(val[1]))
            else:
                vstr = render_value(val, is_port, is_addr)
            print("  [%d] %-10s %s  %-7s %s" % (idx + 1, fname,
                                           MATCH_NAMES.get(mt, "0x%X" % mt),
                                           tname,
                                           vstr))
        print()
    return 0


def _quote(s):
    """命令行参数值: 含空格/引号时用双引号包裹 (内部引号转单引号)"""
    if s is None:
        return '""'
    if any(ch in s for ch in ' \t"\''):
        return '"%s"' % s.replace('"', "'")
    return s


def cond_to_arg(fg, mt, val):
    """条件 → (参数名, 参数值); 无法还原返回 (None, None, 原因)"""
    if fg == COND_IP_PROTOCOL:
        if mt != FWP_MATCH_EQUAL or val[0] != FWP_UINT8:
            return None, None, "协议条件无法还原"
        p = val[1]
        return "--protocol", {6: "tcp", 17: "udp", 1: "icmp",
                              58: "icmpv6"}.get(p, str(p)), None
    if fg in (COND_IP_LOCAL_PORT, COND_IP_REMOTE_PORT):
        arg = "--lport" if fg == COND_IP_LOCAL_PORT else "--rport"
        if mt == FWP_MATCH_EQUAL and val[0] == FWP_UINT16:
            return arg, str(val[1]), None
        if mt == FWP_MATCH_RANGE and val[0] == FWP_RANGE_TYPE:
            (lo_t, lo), (hi_t, hi) = val[1]
            if lo_t == FWP_UINT16 and hi_t == FWP_UINT16:
                return arg, "%d-%d" % (lo, hi), None
        return None, None, "端口条件无法还原"
    if fg in (COND_IP_LOCAL_ADDRESS, COND_IP_REMOTE_ADDRESS):
        arg = "--lip" if fg == COND_IP_LOCAL_ADDRESS else "--rip"
        t, o = val
        if mt == FWP_MATCH_EQUAL and t == FWP_V4_ADDR_MASK:
            addr, mask = o
            pfx = popcount(mask)
            s = ip4(addr)
            return arg, s if pfx == 32 else "%s/%d" % (s, pfx), None
        if mt == FWP_MATCH_EQUAL and t == FWP_UINT32:
            return arg, ip4(o), None
        if mt == FWP_MATCH_EQUAL and t == FWP_V6_ADDR_MASK:
            raw, pfx = o
            s = socket.inet_ntop(socket.AF_INET6, raw)
            return arg, s if pfx == 128 else "%s/%d" % (s, pfx), None
        if mt == FWP_MATCH_RANGE and t == FWP_RANGE_TYPE:
            (lo_t, lo), (hi_t, hi) = o
            if lo_t == FWP_UINT32 and hi_t == FWP_UINT32 and lo <= hi:
                diff = hi - lo + 1
                if diff & (diff - 1) == 0 and (lo & (diff - 1)) == 0:
                    pfx = 32
                    d = diff
                    while d > 1:
                        d >>= 1
                        pfx -= 1
                    return arg, "%s/%d" % (ip4(lo), pfx), None
                return None, None, "地址范围 %s ~ %s 不对齐网段, add 无法精确还原" % (
                    ip4(lo), ip4(hi))
        return None, None, "地址条件无法还原"
    if fg == COND_ALE_APP_ID:
        if mt != FWP_MATCH_EQUAL or val[0] != FWP_BYTE_BLOB_TYPE:
            return None, None, "应用条件无法还原"
        b = val[1]
        if b:
            s = b.decode("utf-16-le").rstrip("\0")
            if s and all(ch.isprintable() or ch in " \t" for ch in s):
                return "--app", _quote(s), None
        return None, None, "应用条件无法还原为路径"
    return None, None, "字段 %s 无法还原" % FIELD_NAMES.get(fg, "{%s}" % fg)


def dump_filter(f):
    print()
    print("# 规则 ID: %d  名称: %s  Key: {%s}" % (
        f["id"], f["name"] or "", f["filterKey"]))
    print("# 复制下面命令执行即可创建等价规则, 修改参数可快速生成新规则:")
    if f["action"] not in (FWP_ACTION_BLOCK, FWP_ACTION_PERMIT):
        print("# 无法还原: 动作类型 0x%X 不是 BLOCK/PERMIT, add 不支持。" % f["action"])
        return
    parts = ["wfpctl add", "--action",
             "block" if f["action"] == FWP_ACTION_BLOCK else "permit"]
    if f["name"]:
        parts += ["--name", _quote(f["name"])]
    if f["desc"]:
        parts += ["--desc", _quote(f["desc"])]
    alias = layer_alias_of(f["layer"])
    parts += ["--layer", alias or ("{%s}" % f["layer"])]
    if f["sublayer"] != WFPCTL_SUBLAYER:
        parts += ["--sublayer", "{%s}" % f["sublayer"]]
    if f["flags"] & FWPM_FILTER_FLAG_BOOTTIME:
        parts.append("--boottime")
    elif not (f["flags"] & FWPM_FILTER_FLAG_PERSISTENT):
        parts.append("--volatile")
    if f["weight"] and f["weight"][0] == FWP_UINT8:
        parts += ["--weight", str(f["weight"][1])]

    mapped = set()
    notes = []
    for (fg, mt, val) in f["conds"]:
        arg_name, arg_val, note = cond_to_arg(fg, mt, val)
        if arg_name is None:
            if note and note not in notes:
                notes.append(note)
            continue
        if fg in mapped and fg not in (COND_IP_LOCAL_ADDRESS, COND_IP_REMOTE_ADDRESS):
            n = "原规则含多个 %s 条件 (与运算), 一条命令只能还原第一个" % (
                FIELD_NAMES.get(fg, "{%s}" % fg))
            if n not in notes:
                notes.append(n)
            continue
        mapped.add(fg)
        parts += [arg_name, arg_val]
    print(" ".join(parts))
    for n in notes:
        print("# 注: " + n)
    print("# 执行后返回新规则 ID; 需管理员权限。")


def cmd_dump(argv):
    if len(argv) == 1 and argv[0] != "--name":
        try:
            fid = int(argv[0])
        except ValueError:
            print("dump: 规则 ID 必须是数字 (可先用 list 查看)。")
            return 1
        by_id = True
    elif len(argv) == 2 and argv[0] == "--name":
        name_filter = argv[1]
        by_id = False
    else:
        print("用法: wfpctl.py dump <规则ID>   或   wfpctl.py dump --name <关键字>")
        return 1

    with WfpEngine() as eng:
        if by_id:
            fs = [eng.get_filter(fid)]
        else:
            fs = []
            for f in eng.enum_filters():
                if (f["name"] and name_filter.lower() in f["name"].lower()) or \
                   (f["desc"] and name_filter.lower() in f["desc"].lower()):
                    fs.append(f)
        if not fs:
            print("dump: 未找到匹配的规则。")
            return 1
        for f in fs:
            dump_filter(f)
    return 0


def cmd_layers(_):
    with WfpEngine() as eng:
        layers = eng.enum_layers()
        print()
        print("本机 WFP 过滤层 (共 %d 个):" % len(layers))
        print("-" * 78)
        for l in layers:
            alias = layer_alias_of(l["key"])
            mark = "  <-- 可用别名: " + alias if alias else ""
            name = (l["name"] or "<无名>")[:34]
            print("%-34s {%s}%s" % (name, l["key"], mark))
            if l["desc"]:
                print("    " + l["desc"])
    return 0


def cmd_sublayers(_):
    with WfpEngine() as eng:
        subs = eng.enum_sublayers()
        print()
        print("本机 WFP 子层 (共 %d 个):" % len(subs))
        print("-" * 78)
        for s in subs:
            mark = "   [本工具默认子层]" if s["key"] == WFPCTL_SUBLAYER else ""
            name = (s["name"] or "<无名>")[:30]
            print("权重 %04X  %-30s {%s}%s" % (s["weight"], name, s["key"], mark))
    return 0


def cmd_sublayer_add(argv):
    if len(argv) not in (2, 3):
        print("用法: wfpctl.py sublayer-add <GUID|default> <名称> [权重0-65535]")
        return 1
    key = WFPCTL_SUBLAYER if argv[0] == "default" else resolve_layer(argv[0])
    if key is None:
        print("sublayer-add: 无效的 GUID。")
        return 1
    weight = 0x100
    if len(argv) == 3:
        try:
            weight = int(argv[2])
        except ValueError:
            weight = -1
        if weight < 0 or weight > 65535:
            print("sublayer-add: 权重须为 0-65535。")
            return 1
    with WfpEngine() as eng:
        check(eng.ensure_sublayer(key, argv[1], weight), "添加子层")
        print("子层已就绪: {%s} 名称 = %s" % (key, argv[1]))
    return 0


def cmd_sublayer_del(argv):
    if len(argv) != 1:
        print("用法: wfpctl.py sublayer-del <GUID|default>")
        return 1
    key = WFPCTL_SUBLAYER if argv[0] == "default" else resolve_layer(argv[0])
    if key is None:
        print("sublayer-del: 无效的 GUID。")
        return 1
    g = GUID()
    guid_set(g, key)
    with WfpEngine() as eng:
        hr = FwpmSubLayerDeleteByKey0(eng.h, ctypes.byref(g))
        if hr != 0:
            u = hr & 0xFFFFFFFF
            if u == 0x80320007:
                print("sublayer-del: 未找到该子层。")
            elif u == 0x8032000A:
                print("sublayer-del: 该子层下仍有过滤规则, 请先删除其规则。")
            else:
                print("错误: 删除子层失败: %s" % hr_msg(hr))
            return 1
        print("已删除子层: {%s}" % key)
    return 0


def usage():
    print()
    print("wfpctl.py —— Windows 过滤平台 (WFP) 过滤规则管理工具  v1.8 (Python 版)")
    print()
    print("用法: python wfpctl.py <命令> [选项]")
    print()
    print("命令:")
    print("  add          添加过滤规则")
    print("  del          删除过滤规则 (按 ID 或 --name 按名称)")
    print("  update       修改规则: update <ID> [参数], 未指定的保持原值")
    print("  list         列出过滤规则 (--all 看系统全部, 默认只看本工具建的)")
    print("  show         查看规则详情")
    print("  dump         导出规则为 add 命令: dump <ID> 或 dump --name <关键字>")
    print("  layers       列出本机所有 WFP 过滤层")
    print("  sublayers    列出所有子层")
    print("  sublayer-add 添加子层")
    print("  sublayer-del 删除子层")
    print("  help         显示本帮助")
    print()
    print("add 选项:")
    print('  --name <名称>            规则显示名 (默认 "wfpctl rule")')
    print("  --desc <描述>            规则描述")
    print("  --action <block|permit>  匹配后动作, 默认 permit (放行); 阻断需显式 --action block")
    print("  --layer <层>             过滤层, 别名或 GUID, 默认 connect-v4")
    for alias, _, d in LAYER_ALIASES:
        print("    %-11s  %s" % (alias, d))
    print("  --sublayer <GUID>        所属子层, 默认使用本工具内置子层 (与 exe 版共享)")
    print("  --protocol <p>           协议: tcp|udp|icmp|icmpv6|数字(0-255)")
    print("  --lport <端口>           本地端口: 80 / 80-90 / 80,443 (多值拆成多条规则)")
    print("  --rport <端口>           远程端口, 同上")
    print("  --lip <IP[/掩码]>        本地地址: 10.0.0.5 / 10.0.0.0/8 / IPv6")
    print("  --rip <IP[/掩码]>        远程地址, 同上")
    print('  --app <程序路径>         按应用过滤, 文件必须存在, 如 C:\\path\\app.exe')
    print("  --weight <0-15>          过滤器权重, 同子层内高的先评估 (缺省自动分配);")
    print("                            例如白名单场景: PERMIT 例外用 15, 整体 BLOCK 用 0")
    print("  --boottime               创建为启动时间规则 (BFE 未启动时即生效)")
    print("  --volatile               规则不持久化, 重启 BFE 后消失 (默认持久)")
    print()
    print("list 选项:")
    print("  --all                    列出系统全部过滤规则")
    print("  --name <关键字>          按名称/描述关键字筛选 (不区分大小写, 可与 --all 组合)")
    print("  --action <block|permit>  按动作筛选")
    print("  --layer <层>             按层筛选")
    print("  --sublayer <GUID|名称|default> 按子层筛选 (名称支持模糊匹配, 可命中多个子层)")
    print()
    print("update 选项 (在 add 参数基础上, 未指定的参数保持原值):")
    print("  update <ID> --rport 443        修改远程端口 (单值或单范围)")
    print("  update <ID> --action block     改为阻断")
    print("  update <ID> --rip any          清除远程地址条件 (any 即清除)")
    print("  update <ID> --weight auto      恢复自动权重")
    print("  修改为事务内“删旧+建新”, 规则 ID 会变化, 失败自动回滚。")
    print()
    print("示例:")
    print('  python wfpctl.py add --name "禁出站80端口" --action block --protocol tcp --rport 80')
    print('  python wfpctl.py add --name "禁访问某网段" --action block --rip 203.0.113.0/24')
    print('  python wfpctl.py add --name "白名单" --rip 1.2.3.4 --weight 15')
    print('  python wfpctl.py list --name 80端口')
    print('  python wfpctl.py list --all --name mssec')
    print("  python wfpctl.py show 12345")
    print("  python wfpctl.py dump 12345")
    print("  python wfpctl.py dump --name 80端口")
    print("  python wfpctl.py update 12345 --rport 443")
    print("  python wfpctl.py del 12345")
    print('  python wfpctl.py del --name "禁出站80端口"')
    print()
    print("说明:")
    print("  * 增删规则需要管理员权限 (依赖系统 BFE 服务)。")
    print("  * 规则默认持久化, 重启系统后仍生效; 与 wfpctl.exe 共用同一子层, 可互相管理。")
    print("  * 端口范围按网络字节序数值区间匹配, 跨高字节块的范围 (如 1000-2000)")
    print("    会被 BFE 拒绝, 此时请改用逗号列举端口。")
    print()


# ---------------------------------------------------------------------------
# 自检 + 入口
# ---------------------------------------------------------------------------
def self_check():
    """验证关键结构体布局 (x64): 布局错误时立即报错, 避免读写野指针"""
    assert ctypes.sizeof(FWP_VALUE0) == 16, "FWP_VALUE0 布局错误"
    assert ctypes.sizeof(FWP_RANGE0) == 32, "FWP_RANGE0 布局错误"
    assert ctypes.sizeof(FWPM_ACTION0) == 24, "FWPM_ACTION0 布局错误"
    assert ctypes.sizeof(FWPM_FILTER_CONDITION0) == 40, "条件布局错误"
    assert ctypes.sizeof(FilterContextUnion) == 16, "context union 布局错误"
    assert ctypes.sizeof(FWPM_FILTER0) == 200, "FWPM_FILTER0 布局错误 (非 x64?)"
    assert ctypes.sizeof(FWPM_LAYER0) == 64, "层布局错误"


def main(argv):
    if not argv:
        usage()
        return 1
    self_check()
    cmd = argv[0].lower()
    rest = argv[1:]
    try:
        if cmd == "add":
            return cmd_add(rest)
        if cmd in ("del", "delete"):
            return cmd_del(rest)
        if cmd == "dump":
            return cmd_dump(rest)
        if cmd in ("update", "upd"):
            return cmd_update(rest)
        if cmd in ("list", "ls"):
            return cmd_list(rest)
        if cmd == "show":
            return cmd_show(rest)
        if cmd == "layers":
            return cmd_layers(rest)
        if cmd == "sublayers":
            return cmd_sublayers(rest)
        if cmd == "sublayer-add":
            return cmd_sublayer_add(rest)
        if cmd == "sublayer-del":
            return cmd_sublayer_del(rest)
        if cmd in ("help", "--help", "-h", "/?"):
            usage()
            return 0
    except WfpError as e:
        print("错误: " + e.msg)
        if e.hr:
            print("(HRESULT = %s)" % hr_msg(e.hr))
        return 1
    except Exception as e:
        print("错误: %s: %s" % (type(e).__name__, e))
        return 1
    print("未知命令: " + argv[0])
    usage()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
