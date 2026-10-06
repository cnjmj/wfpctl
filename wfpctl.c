/* ============================================================================
 *  wfpctl.c —— Windows 过滤平台 (WFP) 过滤规则管理命令行工具 (C 版)
 *
 *  与 wfpctl.exe (C# 版) / wfpctl.py (Python 版) 功能一致:
 *    add / del / list / show / layers / sublayers / sublayer-add / sublayer-del
 *
 *  设计特点 (零外部依赖, 任何 C 编译器可编译):
 *    * 不依赖 Windows SDK 头文件 —— WFP 结构体照 SDK 原文内嵌声明
 *    * 不依赖导入库        —— 运行时 LoadLibrary("fwpuclnt.dll") 动态绑定
 *    * 仅链接 ws2_32 (inet_pton/inet_ntop/htons/ntohs)
 *
 *  编译 (本机, 经 PyPI ziglang 工具链):
 *    python -m ziglang cc -target x86_64-windows-gnu -O2 \
 *        -o wfpctl_c.exe wfpctl.c -lws2_32
 *  编译 (其他环境, MSVC / MinGW 同理):
 *    cl /O2 wfpctl.c ws2_32.lib      或
 *    gcc -O2 -o wfpctl_c.exe wfpctl.c -lws2_32
 *
 *  运行: 增删操作需要管理员权限 (依赖系统 BFE 服务)。
 *
 *  说明: 结构体布局与官方 SDK fwpmtypes.h / fwptypes.h 严格对应;
 *        启动时自检关键尺寸 (x64: W_FILTER0 = 200 字节)。
 *        BFE 返回的内存在 FwpmFreeMemory0 / 下一次枚举前失效,
 *        所有读取均在批内完成 (与 C#/Python 版相同原则)。
 * ========================================================================== */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

/* ==========================================================================
 * WFP 类型 (自包含声明, 照 SDK 原文; GUID 类型由 windows.h 提供)
 * ======================================================================== */
typedef struct W_DISPLAY_DATA0_ {
    wchar_t* name;
    wchar_t* description;
} W_DISPLAY_DATA0;

typedef struct W_BYTE_BLOB_ {
    unsigned int  size;
    void*         data;
} W_BYTE_BLOB;

/* FWP_VALUE0 / FWP_CONDITION_VALUE0 共用: UINT32 type + union(8) = 16 字节 */
typedef union W_VALUE_UNION_ {
    unsigned char   uint8;
    unsigned short  uint16;
    unsigned int    uint32;
    float           float32;
    void*           ptr;   /* 指向 uint64/int64/double/byteArray16/blob/sid/v4mask/v6mask/range */
} W_VALUE_UNION;

typedef struct W_VALUE0_ {
    unsigned int   type;          /* FWP_DATA_TYPE */
    W_VALUE_UNION  value;
} W_VALUE0;

typedef struct W_RANGE0_ {
    W_VALUE0 low;
    W_VALUE0 high;
} W_RANGE0;

typedef struct W_V4_ADDR_AND_MASK_ {
    unsigned int addr;            /* 网络字节序 */
    unsigned int mask;             /* 网络字节序 */
} W_V4_ADDR_AND_MASK;

/* FWP_V6_ADDR_AND_MASK 实际是 17 字节: { UINT8 addr[16]; UINT8 prefixLength; } */
typedef struct W_V6_ADDR_AND_MASK_ {
    unsigned char addr[16];
    unsigned char prefixLength;
} W_V6_ADDR_AND_MASK;

/* MIDL: UINT32 type + union{GUID filterType; GUID calloutKey;} */
typedef struct W_ACTION0_ {
    unsigned int type;
    union { GUID filterType; GUID calloutKey; } u;
} W_ACTION0;

typedef struct W_FILTER_CONDITION0_ {
    GUID           fieldKey;
    unsigned int   matchType;      /* FWP_MATCH_TYPE */
    W_VALUE0       conditionValue;
} W_FILTER_CONDITION0;

typedef struct W_FILTER0_ {
    GUID                   filterKey;            /*   0 */
    W_DISPLAY_DATA0       displayData;          /*  16 */
    unsigned int           flags;                /*  32 */
    GUID*                  providerKey;          /*  40 */
    W_BYTE_BLOB            providerData;         /*  48 */
    GUID                   layerKey;             /*  64 */
    GUID                   subLayerKey;          /*  80 */
    W_VALUE0               weight;               /*  96 */
    unsigned int           numFilterConditions;  /* 112 */
    W_FILTER_CONDITION0*   filterCondition;      /* 120 */
    W_ACTION0              action;               /* 128 */
    union {                                      /* 152 */
        unsigned long long rawContext;
        GUID               providerContextKey;
    } context;
    GUID*                  reserved;             /* 168 */
    unsigned long long     filterId;             /* 176 */
    W_VALUE0               effectiveWeight;      /* 184 */
} W_FILTER0;                                      /* 200 */

typedef struct W_SUB_LAYER0_ {
    GUID               subLayerKey;
    W_DISPLAY_DATA0   displayData;
    unsigned int       flags;
    GUID*              providerKey;
    W_BYTE_BLOB        providerData;
    unsigned short     weight;
} W_SUB_LAYER0;

typedef struct W_LAYER0_ {
    GUID               layerKey;
    W_DISPLAY_DATA0   displayData;
    unsigned int       flags;
    unsigned int       numFields;
    void*              field;
    GUID               defaultSubLayerKey;
} W_LAYER0;

/* ==========================================================================
 * 常量 (fwptypes.h / fwpmtypes.h)
 * ======================================================================== */
#define FWP_ACTION_BLOCK   (0x00000001u | 0x00001000u)
#define FWP_ACTION_PERMIT  (0x00000002u | 0x00001000u)

#define WF_FLAG_PERSISTENT 0x00000001u
#define WF_FLAG_BOOTTIME   0x00000002u
#define WF_FLAG_DISABLED   0x00000020u
#define WF_FLAG_INDEXED    0x00000040u

#define WSL_FLAG_PERSISTENT 0x00000001u

#define FWP_MATCH_EQUAL 0
#define FWP_MATCH_RANGE 5

#define FWP_EMPTY          0
#define FWP_UINT8          1
#define FWP_UINT16         2
#define FWP_UINT32         3
#define FWP_UINT64         4
#define FWP_INT8           5
#define FWP_INT16          6
#define FWP_INT32          7
#define FWP_INT64          8
#define FWP_FLOAT          9
#define FWP_DOUBLE         10
#define FWP_BYTE_ARRAY16   11
#define FWP_BYTE_BLOB      12
#define FWP_SID            13
#define FWP_SECURITY_DESC  14
#define FWP_UNICODE_STRING 17
#define FWP_V4_ADDR_MASK   0x100
#define FWP_V6_ADDR_MASK   0x101
#define FWP_RANGE_TYPE     0x102

/* ---- WFP 常量 GUID (取自官方 SDK fwpmu.h) ---- */
static const GUID LAYER_AUTH_CONNECT_V4 = {0xc38d57d1,0x05a7,0x4c33,{0x90,0x4f,0x7f,0xbc,0xee,0xe6,0x0e,0x82}};
static const GUID LAYER_AUTH_CONNECT_V6 = {0x4a72393b,0x319f,0x44bc,{0x84,0xc3,0xba,0x54,0xdc,0xb3,0xb6,0xb4}};
static const GUID LAYER_AUTH_ACCEPT_V4  = {0xe1cd9fe7,0xf4b5,0x4273,{0x96,0xc0,0x59,0x2e,0x48,0x7b,0x86,0x50}};
static const GUID LAYER_AUTH_ACCEPT_V6  = {0xa3b42c97,0x9f04,0x4672,{0xb8,0x7e,0xce,0xe9,0xc4,0x83,0x25,0x7f}};
static const GUID LAYER_OUT_TRANSPORT_V4 = {0x09e61aea,0xd214,0x46e2,{0x9b,0x21,0xb2,0x6b,0x0b,0x2f,0x28,0xc8}};
static const GUID LAYER_OUT_TRANSPORT_V6 = {0xe1735bde,0x013f,0x4655,{0xb3,0x51,0xa4,0x9e,0x15,0x76,0x2d,0xf0}};
static const GUID LAYER_IN_TRANSPORT_V4  = {0x5926dfc8,0xe3cf,0x4426,{0xa2,0x83,0xdc,0x39,0x3f,0x5d,0x0f,0x9d}};
static const GUID LAYER_IN_TRANSPORT_V6  = {0x634a869f,0xfc23,0x4b90,{0xb0,0xc1,0xbf,0x62,0x0a,0x36,0xae,0x6f}};

static const GUID COND_IP_PROTOCOL     = {0x3971ef2b,0x623e,0x4f9a,{0x8c,0xb1,0x6e,0x79,0xb8,0x06,0xb9,0xa7}};
static const GUID COND_IP_LOCAL_ADDR   = {0xd9ee00de,0xc1ef,0x4617,{0xbf,0xe3,0xff,0xd8,0xf5,0xa0,0x89,0x57}};
static const GUID COND_IP_REMOTE_ADDR  = {0xb235ae9a,0x1d64,0x49b8,{0xa4,0x4c,0x5f,0xf3,0xd9,0x09,0x50,0x45}};
static const GUID COND_IP_LOCAL_PORT   = {0x0c1ba1af,0x5765,0x453f,{0xaf,0x22,0xa8,0xf7,0x91,0xac,0x77,0x5b}};
static const GUID COND_IP_REMOTE_PORT  = {0xc35a604d,0xd22b,0x4e1a,{0x91,0xb4,0x68,0xf6,0x74,0xee,0x67,0x4b}};
static const GUID COND_ALE_APP_ID      = {0xd78e1e87,0x8644,0x4ea5,{0x94,0x37,0xd8,0x09,0xec,0xef,0xc9,0x71}};
static const GUID COND_ALE_USER_ID     = {0xaf043a0a,0xb34d,0x4f86,{0x97,0x9c,0xc9,0x03,0x71,0xaf,0x6e,0x66}};
static const GUID COND_IPSEC_QM_SA_ID  = {0x4cd62a49,0x59c3,0x4969,{0xb7,0xf3,0xbd,0xa5,0xd3,0x28,0x90,0xa4}};

/* 本工具默认子层 (与 C#/Python 版相同 GUID, 三版共用、可互相管理) */
static const GUID WFPCTL_SUBLAYER = {0xb7c4f2a1,0x3e5d,0x4a90,{0x8b,0x1c,0x6f,0x2e,0x7d,0x8a,0x9b,0x3c}};
static const wchar_t* TOOL_SUBLAYER_NAME = L"wfpctl rules";

/* ==========================================================================
 * fwpuclnt.dll 动态绑定 (不依赖导入库)
 * ======================================================================== */
typedef long  (WINAPI* PFN_EngineOpen)(const wchar_t*, unsigned int, void*, const void*, void**);
typedef void  (WINAPI* PFN_EngineClose)(void*);
typedef long  (WINAPI* PFN_TxnBegin)(void*, unsigned int);
typedef long  (WINAPI* PFN_TxnEnd)(void*);
typedef long  (WINAPI* PFN_FilterAdd)(void*, W_FILTER0*, void*, unsigned long long*);
typedef long  (WINAPI* PFN_FilterDelById)(void*, unsigned long long);
typedef long  (WINAPI* PFN_FilterGetById)(void*, unsigned long long, void**);
typedef long  (WINAPI* PFN_EnumCreate)(void*, const void*, void**);
typedef long  (WINAPI* PFN_FilterEnum)(void*, void*, unsigned int, void***, unsigned int*);
typedef long  (WINAPI* PFN_EnumDestroy)(void*, void*);
typedef long  (WINAPI* PFN_SubLayerAdd)(void*, W_SUB_LAYER0*, void*);
typedef long  (WINAPI* PFN_SubLayerDelByKey)(void*, const GUID*);
typedef long  (WINAPI* PFN_SubLayerEnum)(void*, void*, unsigned int, void***, unsigned int*);
typedef long  (WINAPI* PFN_LayerEnum)(void*, void*, unsigned int, void***, unsigned int*);
typedef void  (WINAPI* PFN_FreeMemory)(void**);
typedef unsigned int (WINAPI* PFN_GetAppId)(const wchar_t*, void**);

static PFN_EngineOpen      pFwpmEngineOpen0;
static PFN_EngineClose     pFwpmEngineClose0;
static PFN_TxnBegin        pFwpmTransactionBegin0;
static PFN_TxnEnd          pFwpmTransactionCommit0;
static PFN_TxnEnd          pFwpmTransactionAbort0;
static PFN_FilterAdd       pFwpmFilterAdd0;
static PFN_FilterDelById   pFwpmFilterDeleteById0;
static PFN_FilterGetById   pFwpmFilterGetById0;
static PFN_EnumCreate      pFwpmFilterCreateEnumHandle0;
static PFN_FilterEnum      pFwpmFilterEnum0;
static PFN_EnumDestroy     pFwpmFilterDestroyEnumHandle0;
static PFN_SubLayerAdd     pFwpmSubLayerAdd0;
static PFN_SubLayerDelByKey pFwpmSubLayerDeleteByKey0;
static PFN_EnumCreate      pFwpmSubLayerCreateEnumHandle0;
static PFN_SubLayerEnum    pFwpmSubLayerEnum0;
static PFN_EnumDestroy     pFwpmSubLayerDestroyEnumHandle0;
static PFN_EnumCreate      pFwpmLayerCreateEnumHandle0;
static PFN_LayerEnum       pFwpmLayerEnum0;
static PFN_EnumDestroy     pFwpmLayerDestroyEnumHandle0;
static PFN_FreeMemory      pFwpmFreeMemory0;
static PFN_GetAppId        pFwpmGetAppIdFromFileName0;

/* advapi32 / shell32 (动态, 避免再链导入库) */
typedef int (WINAPI* PFN_ConvSid)(void*, wchar_t**);
typedef int (WINAPI* PFN_ConvSD)(void*, unsigned int, unsigned int, wchar_t**, unsigned int*);
typedef void (WINAPI* PFN_LocalFree)(void*);
typedef wchar_t ** (WINAPI* PFN_ArgvW)(const wchar_t*, int*);
static PFN_ConvSid   pConvertSidToStringSidW;
static PFN_ConvSD    pConvertSDtoSDR;
static PFN_LocalFree pLocalFree;
static PFN_ArgvW     pCommandLineToArgvW;

static int wfp_bind(void)
{
    HMODULE m = LoadLibraryW(L"fwpuclnt.dll");
    if (!m) { fprintf(stderr, "错误: 无法加载 fwpuclnt.dll (系统缺少 BFE 客户端)。\n"); return 0; }
    /* 逐个 GetProcAddress 绑定 */
    pFwpmEngineOpen0 = (PFN_EngineOpen)GetProcAddress(m, "FwpmEngineOpen0");
    pFwpmEngineClose0 = (PFN_EngineClose)GetProcAddress(m, "FwpmEngineClose0");
    pFwpmTransactionBegin0 = (PFN_TxnBegin)GetProcAddress(m, "FwpmTransactionBegin0");
    pFwpmTransactionCommit0 = (PFN_TxnEnd)GetProcAddress(m, "FwpmTransactionCommit0");
    pFwpmTransactionAbort0 = (PFN_TxnEnd)GetProcAddress(m, "FwpmTransactionAbort0");
    pFwpmFilterAdd0 = (PFN_FilterAdd)GetProcAddress(m, "FwpmFilterAdd0");
    pFwpmFilterDeleteById0 = (PFN_FilterDelById)GetProcAddress(m, "FwpmFilterDeleteById0");
    pFwpmFilterGetById0 = (PFN_FilterGetById)GetProcAddress(m, "FwpmFilterGetById0");
    pFwpmFilterCreateEnumHandle0 = (PFN_EnumCreate)GetProcAddress(m, "FwpmFilterCreateEnumHandle0");
    pFwpmFilterEnum0 = (PFN_FilterEnum)GetProcAddress(m, "FwpmFilterEnum0");
    pFwpmFilterDestroyEnumHandle0 = (PFN_EnumDestroy)GetProcAddress(m, "FwpmFilterDestroyEnumHandle0");
    pFwpmSubLayerAdd0 = (PFN_SubLayerAdd)GetProcAddress(m, "FwpmSubLayerAdd0");
    pFwpmSubLayerDeleteByKey0 = (PFN_SubLayerDelByKey)GetProcAddress(m, "FwpmSubLayerDeleteByKey0");
    pFwpmSubLayerCreateEnumHandle0 = (PFN_EnumCreate)GetProcAddress(m, "FwpmSubLayerCreateEnumHandle0");
    pFwpmSubLayerEnum0 = (PFN_SubLayerEnum)GetProcAddress(m, "FwpmSubLayerEnum0");
    pFwpmSubLayerDestroyEnumHandle0 = (PFN_EnumDestroy)GetProcAddress(m, "FwpmSubLayerDestroyEnumHandle0");
    pFwpmLayerCreateEnumHandle0 = (PFN_EnumCreate)GetProcAddress(m, "FwpmLayerCreateEnumHandle0");
    pFwpmLayerEnum0 = (PFN_LayerEnum)GetProcAddress(m, "FwpmLayerEnum0");
    pFwpmLayerDestroyEnumHandle0 = (PFN_EnumDestroy)GetProcAddress(m, "FwpmLayerDestroyEnumHandle0");
    pFwpmFreeMemory0 = (PFN_FreeMemory)GetProcAddress(m, "FwpmFreeMemory0");
    pFwpmGetAppIdFromFileName0 = (PFN_GetAppId)GetProcAddress(m, "FwpmGetAppIdFromFileName0");
    if (!pFwpmEngineOpen0 || !pFwpmEngineClose0 || !pFwpmTransactionBegin0 ||
        !pFwpmTransactionCommit0 || !pFwpmTransactionAbort0 || !pFwpmFilterAdd0 ||
        !pFwpmFilterDeleteById0 || !pFwpmFilterGetById0 || !pFwpmFilterCreateEnumHandle0 ||
        !pFwpmFilterEnum0 || !pFwpmFilterDestroyEnumHandle0 || !pFwpmSubLayerAdd0 ||
        !pFwpmSubLayerDeleteByKey0 || !pFwpmSubLayerCreateEnumHandle0 || !pFwpmSubLayerEnum0 ||
        !pFwpmSubLayerDestroyEnumHandle0 || !pFwpmLayerCreateEnumHandle0 || !pFwpmLayerEnum0 ||
        !pFwpmLayerDestroyEnumHandle0 || !pFwpmFreeMemory0 || !pFwpmGetAppIdFromFileName0)
    { fprintf(stderr, "错误: fwpuclnt.dll 导出函数缺失。\n"); return 0; }

    {
        HMODULE adv = LoadLibraryW(L"advapi32.dll");
        HMODULE sh = LoadLibraryW(L"shell32.dll");
        if (adv) pConvertSidToStringSidW = (PFN_ConvSid)GetProcAddress(adv, "ConvertSidToStringSidW");
        if (adv) pConvertSDtoSDR = (PFN_ConvSD)GetProcAddress(adv, "ConvertSecurityDescriptorToStringSecurityDescriptorW");
        if (sh)  pCommandLineToArgvW = (PFN_ArgvW)GetProcAddress(sh, "CommandLineToArgvW");
        HMODULE kr = LoadLibraryW(L"kernel32.dll");
        if (kr)  pLocalFree = (PFN_LocalFree)GetProcAddress(kr, "LocalFree");
        if (!pCommandLineToArgvW)
        { fprintf(stderr, "错误: 无法绑定 CommandLineToArgvW。\n"); return 0; }
    }
    return 1;
}

/* ==========================================================================
 * 工具函数
 * ======================================================================== */
static int g_err(const char* what, long hr)
{
    fprintf(stderr, "错误: %s 失败: 0x%08X\n", what, (unsigned int)hr);
    return 1;
}

static int hexv(wchar_t c)
{
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

/* 手写 GUID 解析: "{...}" 或 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" */
static int parse_guid(const wchar_t* s, GUID* g)
{
    unsigned int v[32];
    int i, n = 0;
    memset(g, 0, sizeof(*g));
    if (*s == L'{') s++;
    for (i = 0; i < 36 && s[i]; i++)
    {
        if (n >= 32) return 0;
        if (s[i] == L'-') continue;
        {
            int h = hexv(s[i]);
            if (h < 0) return 0;
            v[n++] = (unsigned int)h;
        }
    }
    if (n != 32) return 0;
    g->Data1  = (v[0] << 28) | (v[1] << 24) | (v[2] << 20) | (v[3] << 16)
              | (v[4] << 12) | (v[5] << 8)  | (v[6] << 4)  |  v[7];
    g->Data2  = (unsigned short)((v[8] << 12) | (v[9] << 8) | (v[10] << 4) | v[11]);
    g->Data3  = (unsigned short)((v[12] << 12) | (v[13] << 8) | (v[14] << 4) | v[15]);
    for (i = 0; i < 8; i++)
        g->Data4[i] = (unsigned char)((v[16 + 2 * i] << 4) | v[17 + 2 * i]);
    return 1;
}

static int fmt_guid(const GUID* g, char* buf, size_t n)
{
    return snprintf(buf, n,
        "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        (unsigned long)g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
        g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]) > 0;
}

static int guid_eq(const GUID* a, const GUID* b)
{
    return memcmp(a, b, sizeof(GUID)) == 0;
}

/* 宽字符串 → UTF-8 (仅用于终端显示; 调用方负责 free) */
static char* w2u(const wchar_t* s)
{
    int n;
    char* p;
    if (!s) return NULL;
    n = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    p = (char*)malloc((size_t)n);
    if (!p) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, s, -1, p, n, NULL, NULL);
    return p;
}

static wchar_t* wdup(const wchar_t* s)
{
    size_t n;
    wchar_t* p;
    if (!s) return NULL;
    n = wcslen(s) + 1;
    p = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (p) wcscpy(p, s);
    return p;
}

/* 大小写不敏感宽字符串子串匹配 (hay 含 needle 返回 1) */
static int wcasestr(const wchar_t* hay, const wchar_t* needle)
{
    size_t n;
    if (!hay || !needle) return 0;
    n = wcslen(needle);
    if (n == 0) return 1;
    for (; *hay; hay++)
    {
        size_t k = 0;
        while (k < n && hay[k] && towlower((wint_t)hay[k]) == towlower((wint_t)needle[k])) k++;
        if (k == n) return 1;
    }
    return 0;
}

static int popcount32(unsigned int x)
{
    int n = 0;
    while (x) { n += (int)(x & 1u); x >>= 1; }
    return n;
}

/* ---- 层别名 ---- */
typedef struct { const wchar_t* alias; const GUID* guid; const char* desc; } LayerAlias;
static const LayerAlias g_layers[] = {
    { L"connect-v4", &LAYER_AUTH_CONNECT_V4, "出站连接授权 (ALE)" },
    { L"connect-v6", &LAYER_AUTH_CONNECT_V6, "出站连接授权 (ALE, IPv6)" },
    { L"accept-v4",  &LAYER_AUTH_ACCEPT_V4,  "入站连接授权 (ALE)" },
    { L"accept-v6",  &LAYER_AUTH_ACCEPT_V6,  "入站连接授权 (ALE, IPv6)" },
    { L"out-v4",     &LAYER_OUT_TRANSPORT_V4, "出站传输层" },
    { L"out-v6",     &LAYER_OUT_TRANSPORT_V6, "出站传输层 (IPv6)" },
    { L"in-v4",      &LAYER_IN_TRANSPORT_V4,  "入站传输层" },
    { L"in-v6",      &LAYER_IN_TRANSPORT_V6,  "入站传输层 (IPv6)" },
};

static const wchar_t* layer_alias_of(const GUID* g)
{
    int i;
    for (i = 0; i < (int)(sizeof(g_layers) / sizeof(g_layers[0])); i++)
        if (guid_eq(g, g_layers[i].guid)) return g_layers[i].alias;
    return NULL;
}

static int resolve_layer(const wchar_t* s, GUID* out)
{
    int i;
    for (i = 0; i < (int)(sizeof(g_layers) / sizeof(g_layers[0])); i++)
        if (wcscmp(s, g_layers[i].alias) == 0) { *out = *g_layers[i].guid; return 1; }
    return parse_guid(s, out);
}

/* ==========================================================================
 * 引擎封装
 * ======================================================================== */
typedef void* WENGINE;

static int engine_open(WENGINE* h)
{
    long hr = pFwpmEngineOpen0(NULL, 10 /*RPC_C_AUTHN_WINNT*/, NULL, NULL, h);
    if (hr != 0)
    {
        if ((unsigned int)hr == 0x80070005u)
            fprintf(stderr, "错误: 打开 BFE 引擎被拒绝。请以管理员身份运行本工具。\n");
        else
            fprintf(stderr, "错误: 打开 WFP 引擎失败 (FwpmEngineOpen0): 0x%08X\n", (unsigned int)hr);
        return 0;
    }
    return 1;
}

static void engine_close(WENGINE h) { if (h) pFwpmEngineClose0(h); }

/* 确保持久子层存在 (持久 filter 必须挂在持久子层上, 否则 0x80320016) */
static long ensure_sublayer(WENGINE h, const GUID* key, const wchar_t* name, unsigned short weight)
{
    W_SUB_LAYER0 sl;
    long hr;
    memset(&sl, 0, sizeof(sl));
    sl.subLayerKey = *key;
    sl.displayData.name = (wchar_t*)name;
    sl.flags = WSL_FLAG_PERSISTENT;
    sl.weight = weight;
    hr = pFwpmSubLayerAdd0(h, &sl, NULL);
    if ((unsigned int)hr == 0x80320009u) hr = 0;   /* FWP_E_ALREADY_EXISTS */
    return hr;
}

/* ==========================================================================
 * 显示辅助 (全部在 BFE 内存仍有效期间调用)
 * ======================================================================== */
static const char* proto_name(unsigned char b)
{
    switch (b)
    {
        case 1:  return "ICMP (1)";
        case 6:  return "TCP (6)";
        case 17: return "UDP (17)";
        case 47: return "GRE (47)";
        case 58: return "ICMPv6 (58)";
        default: return "";
    }
}

/* SDK fwpmu.h 内置条件字段 GUID → 名称 (工具常用字段之外的全量补充) */
static const struct { GUID key; const wchar_t* name; } g_cond_extra[] = {
    { {0xf6e63dce,0x1f4b,0x4c6b,{0xb6,0xef,0x11,0x65,0xe7,0x1f,0x8e,0xe7}}, L"接口MAC地址" },
    { {0xd999e981,0x7948,0x4c8e,{0xb7,0x42,0xc8,0x4e,0x3b,0x67,0x8f,0x8f}}, L"本地MAC地址" },
    { {0x408f2ed4,0x3a70,0x4b4d,{0x92,0xa6,0x41,0x5a,0xc2,0x0e,0x2f,0x12}}, L"远程MAC地址" },
    { {0xfd08948d,0xa219,0x4d52,{0xbb,0x98,0x1a,0x55,0x40,0xee,0x7b,0x4e}}, L"以太网类型" },
    { {0x938eab21,0x3618,0x4e64,{0x9c,0xa5,0x21,0x41,0xeb,0xda,0x1c,0xa2}}, L"VLAN ID" },
    { {0x7bc43cbf,0x37ba,0x45f1,{0xb7,0x4a,0x82,0xff,0x51,0x8e,0xeb,0x10}}, L"二层标志" },
    { {0xcc31355c,0x3073,0x4ffb,{0xa1,0x4f,0x79,0x41,0x5c,0xb1,0xea,0xd1}}, L"本地MAC地址类型" },
    { {0x027fedb4,0xf1c1,0x4030,{0xb5,0x64,0xee,0x77,0x7f,0xd8,0x67,0xea}}, L"远程MAC地址类型" },
    { {0x71bc78fa,0xf17c,0x4997,{0xa6,0x02,0x6a,0xbb,0x26,0x1f,0x35,0x1c}}, L"应用包ID" },
    { {0x7b795451,0xf1f6,0x4d05,{0xb7,0xcb,0x21,0x77,0x9d,0x80,0x23,0x36}}, L"源MAC地址" },
    { {0x04ea2a93,0x858c,0x4027,{0xb6,0x13,0xb4,0x31,0x80,0xc7,0x85,0x9e}}, L"目的MAC地址" },
    { {0x5c1b72e4,0x299e,0x4437,{0xa2,0x98,0xbc,0x3f,0x01,0x4b,0x3d,0xc2}}, L"源MAC地址类型" },
    { {0xae052932,0xef42,0x4e99,{0xb1,0x29,0xf3,0xb3,0x13,0x9e,0x34,0xf7}}, L"目的MAC地址类型" },
    { {0xa6afef91,0x3df4,0x4730,{0xa2,0x14,0xf5,0x42,0x6a,0xeb,0xf8,0x21}}, L"源端口" },
    { {0xce6def45,0x60fb,0x4a7b,{0xa3,0x04,0xaf,0x30,0xa1,0x17,0x00,0x0e}}, L"目的端口" },
    { {0xae96897e,0x2e94,0x4bc9,{0xb3,0x13,0xb2,0x7e,0xe8,0x0e,0x57,0x4d}}, L"源IP地址" },
    { {0x2d79133b,0xb390,0x45c6,{0x86,0x99,0xac,0xac,0xea,0xaf,0xed,0x33}}, L"目的IP地址" },
    { {0x6ec7f6c4,0x376b,0x45d7,{0x9e,0x9c,0xd3,0x37,0xce,0xdc,0xd2,0x37}}, L"本地地址类型" },
    { {0x1ec1b7c9,0x4eea,0x4f5e,{0xb9,0xef,0x76,0xbe,0xaa,0xaf,0x17,0xee}}, L"目的地址类型" },
    { {0xeabe448a,0xa711,0x4d64,{0x85,0xb7,0x3f,0x76,0xb6,0x52,0x99,0xc7}}, L"下一跳地址" },
    { {0x4cd62a49,0x59c3,0x4969,{0xb7,0xf3,0xbd,0xa5,0xd3,0x28,0x90,0xa4}}, L"本地接口" },
    { {0x618a9b6d,0x386b,0x4136,{0xad,0x6e,0xb5,0x15,0x87,0xcf,0xb1,0xcd}}, L"到达接口" },
    { {0x89f990de,0xe798,0x4e6d,{0xab,0x76,0x7c,0x95,0x58,0x29,0x2e,0x6f}}, L"到达接口类型" },
    { {0x511166dc,0x7a8c,0x4aa7,{0xb5,0x33,0x95,0xab,0x59,0xfb,0x03,0x40}}, L"到达隧道类型" },
    { {0xcc088db3,0x1792,0x4a71,{0xb0,0xf9,0x03,0x7d,0x21,0xcd,0x82,0x8b}}, L"到达接口索引" },
    { {0xef8a6122,0x0577,0x45a7,{0x9a,0xaf,0x82,0x5f,0xbe,0xb4,0xfb,0x95}}, L"下一跳子接口索引" },
    { {0x93ae8f5b,0x7f6f,0x4719,{0x98,0xc8,0x14,0xe9,0x74,0x29,0xef,0x04}}, L"下一跳接口" },
    { {0x97537c6c,0xd9a3,0x4767,{0xa3,0x81,0xe9,0x42,0x67,0x5c,0xd9,0x20}}, L"下一跳接口类型" },
    { {0x72b1a111,0x987b,0x4720,{0x99,0xdd,0xc7,0xc5,0x76,0xfa,0x2d,0x4c}}, L"下一跳隧道类型" },
    { {0x138e6888,0x7ab8,0x4d65,{0x9e,0xe8,0x05,0x91,0xbc,0xf6,0xa4,0x94}}, L"下一跳接口索引" },
    { {0x46ea1551,0x2255,0x492b,{0x80,0x19,0xaa,0xbe,0xee,0x34,0x9f,0x40}}, L"原始配置文件ID" },
    { {0xab3033c9,0xc0e3,0x4759,{0x93,0x7d,0x57,0x58,0xc6,0x5d,0x4a,0xe3}}, L"当前配置文件ID" },
    { {0x4ebf7562,0x9f18,0x4d06,{0x99,0x41,0xa7,0xa6,0x25,0x74,0x4d,0x71}}, L"本地接口配置文件ID" },
    { {0xcdfe6aab,0xc083,0x4142,{0x86,0x79,0xc0,0x8f,0x95,0x32,0x9c,0x61}}, L"到达接口配置文件ID" },
    { {0xd7ff9a56,0xcdaa,0x472b,{0x84,0xdb,0xd2,0x39,0x63,0xc1,0xd1,0xbf}}, L"下一跳接口配置文件ID" },
    { {0x11205e8c,0x11ae,0x457a,{0x8a,0x44,0x47,0x70,0x26,0xdd,0x76,0x4a}}, L"重新授权原因" },
    { {0x076dfdbe,0xc56c,0x4f72,{0xae,0x8a,0x2c,0xfe,0x7e,0x5c,0x82,0x86}}, L"原始ICMP类型" },
    { {0xda50d5c8,0xfa0d,0x4c89,{0xb0,0x32,0x6e,0x62,0x13,0x6d,0x1e,0x96}}, L"物理到达接口" },
    { {0xf09bd5ce,0x5150,0x48be,{0xb0,0x98,0xc2,0x51,0x52,0xfb,0x1f,0x92}}, L"物理下一跳接口" },
    { {0xcce68d5e,0x053b,0x43a8,{0x9a,0x6f,0x33,0x38,0x4c,0x28,0xe4,0xf6}}, L"接口隔离纪元" },
    { {0xdaf8cd14,0xe09e,0x4c93,{0xa5,0xae,0xc5,0xc1,0x3b,0x73,0xff,0xca}}, L"接口类型" },
    { {0x77a40437,0x8779,0x4868,{0xa2,0x61,0xf5,0xa9,0x02,0xf1,0xc0,0xcd}}, L"隧道类型" },
    { {0x1076b8a5,0x6323,0x4c5e,{0x98,0x10,0xe8,0xd3,0xfc,0x9e,0x61,0x36}}, L"IP转发接口" },
    { {0x4672a468,0x8a0a,0x4202,{0xab,0xb4,0x84,0x9e,0x92,0xe6,0x68,0x09}}, L"内嵌本地地址类型" },
    { {0x77ee4b39,0x3273,0x4671,{0xb6,0x3b,0xab,0x6f,0xeb,0x66,0xee,0xb6}}, L"内嵌远程地址" },
    { {0x07784107,0xa29e,0x4c7b,{0x9e,0xc7,0x29,0xc4,0x4a,0xfa,0xfd,0xbc}}, L"内嵌协议" },
    { {0xbfca394d,0xacdb,0x484e,{0xb8,0xe6,0x2a,0xff,0x79,0x75,0x73,0x45}}, L"内嵌本地端口" },
    { {0xcae4d6a1,0x2968,0x40ed,{0xa4,0xce,0x54,0x71,0x60,0xdd,0xa8,0x8d}}, L"内嵌远程端口" },
    { {0x632ce23b,0x5167,0x435c,{0x86,0xd7,0xe9,0x03,0x68,0x4a,0xa8,0x0c}}, L"标志" },
    { {0x8784c146,0xca97,0x44d6,{0x9f,0xd1,0x19,0xfb,0x18,0x40,0xcb,0xf7}}, L"方向" },
    { {0x667fd755,0xd695,0x434a,{0x8a,0xf5,0xd3,0x83,0x5a,0x12,0x59,0xbc}}, L"接口索引" },
    { {0x0cd42473,0xd621,0x4be3,{0xae,0x8c,0x72,0xa3,0x48,0xd2,0x83,0xe1}}, L"子接口索引" },
    { {0x2311334d,0xc92d,0x45bf,{0x94,0x96,0xed,0xf4,0x47,0x82,0x0e,0x2d}}, L"源接口索引" },
    { {0x055edd9d,0xacd2,0x4361,{0x8d,0xab,0xf9,0x52,0x5d,0x97,0x66,0x2f}}, L"源子接口索引" },
    { {0x35cf6522,0x4139,0x45ee,{0xa0,0xd5,0x67,0xb8,0x09,0x49,0xd8,0x79}}, L"目的接口索引" },
    { {0x2b7d4399,0xd4c7,0x4738,{0xa2,0xf5,0xe9,0x94,0xb4,0x3d,0xa3,0x88}}, L"目的子接口索引" },
    { {0x0e6cd086,0xe1fb,0x4212,{0x84,0x2f,0x8a,0x9f,0x99,0x3f,0xb3,0xf6}}, L"原始应用程序" },
    { {0xf63073b7,0x0189,0x4ab0,{0x95,0xa4,0x61,0x23,0xcb,0xfa,0xb8,0x62}}, L"远程用户" },
    { {0x1aa47f51,0x7f93,0x4508,{0xa2,0x71,0x81,0xab,0xb0,0x0c,0x9c,0xab}}, L"远程计算机" },
    { {0x1c974776,0x7182,0x46e9,{0xaf,0xd3,0xb0,0x29,0x10,0xe3,0x03,0x34}}, L"混杂模式" },
    { {0xb482d227,0x1979,0x4a98,{0x80,0x44,0x18,0xbb,0xe6,0x23,0x75,0x42}}, L"ALE重新授权原因" },
    { {0x46275a9d,0xc03f,0x4d77,{0xb7,0x84,0x1c,0x57,0xf4,0xd0,0x27,0x53}}, L"ALE NAP上下文" },
    { {0x37a57699,0x5883,0x4963,{0x92,0xb8,0x3e,0x70,0x46,0x88,0xb0,0xad}}, L"应用安全属性FQBN" },
    { {0xb1277b9a,0xb781,0x40fc,{0x96,0x71,0xe5,0xf1,0xb9,0x89,0xf3,0x4e}}, L"有效名称" },
    { {0x37a57700,0x5884,0x4964,{0x92,0xb8,0x3e,0x70,0x46,0x88,0xb0,0xad}}, L"IPsec安全域ID" },
    { {0x35d0ea0e,0x15ca,0x492b,{0x90,0x0e,0x97,0xfd,0x46,0x35,0x2c,0xce}}, L"IPsec认证NAP上下文" },
    { {0x9bf0ee66,0x06c9,0x41b9,{0x84,0xda,0x28,0x8c,0xb4,0x3a,0xf5,0x1f}}, L"远程用户令牌" },
    { {0x7c9c7d9f,0x0075,0x4d35,{0xa0,0xd1,0x83,0x11,0xc4,0xcf,0x6a,0xf1}}, L"RPC接口UUID" },
    { {0xeabfd9b7,0x1262,0x4a2e,{0xad,0xaa,0x5f,0x96,0xf6,0xfe,0x32,0x6d}}, L"RPC接口版本" },
    { {0x238a8a32,0x3199,0x467d,{0x87,0x1c,0x27,0x26,0x21,0xab,0x38,0x96}}, L"RPC接口标志" },
    { {0xff2e7b4d,0x3112,0x4770,{0xb6,0x36,0x4d,0x24,0xae,0x3a,0x6a,0xf2}}, L"DCOM应用ID" },
    { {0xd024de4d,0xdeaa,0x4317,{0x9c,0x85,0xe4,0x0e,0xf6,0xe1,0x40,0xc3}}, L"镜像名称" },
    { {0x2717bc74,0x3a35,0x4ce7,{0xb7,0xef,0xc8,0x38,0xfa,0xbd,0xec,0x45}}, L"RPC协议" },
    { {0xdaba74ab,0x0d67,0x43e7,{0x98,0x6e,0x75,0xb8,0x4f,0x82,0xf5,0x94}}, L"RPC认证类型" },
    { {0xe5a0aed5,0x59ac,0x46ea,{0xbe,0x05,0xa5,0xf0,0x5e,0xcf,0x44,0x6e}}, L"RPC认证级别" },
    { {0x0d306ef0,0xe974,0x4f74,{0xb5,0xc7,0x59,0x1b,0x0d,0xa7,0xd5,0x62}}, L"加密算法" },
    { {0x4772183b,0xccf8,0x4aeb,{0xbc,0xe1,0xc6,0xc6,0x16,0x1c,0x8f,0xe4}}, L"密钥长度" },
    { {0x1bd0741d,0xe3df,0x4e24,{0x86,0x34,0x76,0x20,0x46,0xee,0xf6,0xeb}}, L"管道" },
    { {0xe31180a8,0xbbbd,0x4d14,{0xa6,0x5e,0x71,0x57,0xb0,0x62,0x33,0xbb}}, L"RPC进程UUID" },
    { {0xdccea0b9,0x0886,0x4360,{0x9c,0x6a,0xab,0x04,0x3a,0x24,0xfb,0xa9}}, L"RPC端点值" },
    { {0x218b814a,0x0a39,0x49b8,{0x8e,0x71,0xc2,0x0c,0x39,0xc7,0xdd,0x2e}}, L"RPC端点标志" },
    { {0xc228fc1e,0x403a,0x4478,{0xbe,0x05,0xc9,0xba,0xa4,0xc0,0x5a,0xce}}, L"客户端令牌" },
    { {0xb605a225,0xc3b3,0x48c7,{0x98,0x33,0x7a,0xef,0xa9,0x52,0x75,0x46}}, L"RPC服务器名" },
    { {0x8090f645,0x9ad5,0x4e3b,{0x9f,0x9f,0x80,0x23,0xca,0x09,0x79,0x09}}, L"RPC服务器端口" },
    { {0x40953fe2,0x8565,0x4759,{0x84,0x88,0x17,0x71,0xb4,0xb4,0xb5,0xdb}}, L"RPC代理认证类型" },
    { {0xa3ec00c7,0x05f4,0x4df7,{0x91,0xf2,0x5f,0x60,0xd9,0x1f,0xf4,0x43}}, L"客户端证书密钥长度" },
    { {0xc491ad5e,0xf882,0x4283,{0xb9,0x16,0x43,0x6b,0x10,0x3f,0xf4,0xad}}, L"客户端证书OID" },
    { {0x206e9996,0x490e,0x40cf,{0xb8,0x31,0xb3,0x86,0x41,0xeb,0x6f,0xcb}}, L"网络事件类型" },
    { {0x9b539082,0xeb90,0x4186,{0xa6,0xcc,0xde,0x5b,0x63,0x23,0x50,0x16}}, L"对等名称" },
    { {0xf68166fd,0x0682,0x4c89,{0xb8,0xf5,0x86,0x43,0x6c,0x7e,0xf9,0xb7}}, L"远程ID" },
    { {0xeb458cd5,0xda7b,0x4ef9,{0x8d,0x43,0x7b,0x0a,0x84,0x03,0x32,0xf2}}, L"认证类型" },
    { {0xff0f5f49,0x0ceb,0x481b,{0x86,0x38,0x14,0x79,0x79,0x1f,0x3f,0x2c}}, L"密钥管理类型" },
    { {0xfeef4582,0xef8f,0x4f7b,{0x85,0x8b,0x90,0x77,0xd1,0x22,0xde,0x47}}, L"密钥管理模式" },
    { {0xad37dee3,0x722f,0x45cc,{0xa4,0xe3,0x06,0x80,0x48,0x12,0x44,0x52}}, L"IPsec策略Key" },
    { {0xf64fc6d1,0xf9cb,0x43d2,{0x8a,0x5f,0xe1,0x3b,0xc8,0x94,0xf2,0x65}}, L"IPsec快速模式" },
    { {0xdc04843c,0x79e6,0x4e44,{0xa0,0x25,0x65,0xb9,0xbb,0x0f,0x9f,0x94}}, L"vSwitch租户网络ID" },
    { {0xc4a414ba,0x437b,0x4de6,{0x99,0x46,0xd9,0x9c,0x1b,0x95,0xb3,0x12}}, L"vSwitch ID" },
    { {0x11d48b4b,0xe77a,0x40b4,{0x91,0x55,0x39,0x2c,0x90,0x6c,0x26,0x08}}, L"vSwitch网络类型" },
    { {0xdb7bb42b,0x2dac,0x4cd4,{0xa5,0x9a,0xe0,0xbd,0xce,0x1e,0x68,0x34}}, L"NDIS端口" },
};

/* 配置文件 ID 字段 (值解码: 1=域 2=专用 4=公用) */
static const GUID g_profile_keys[5] = {
    {0x46ea1551,0x2255,0x492b,{0x80,0x19,0xaa,0xbe,0xee,0x34,0x9f,0x40}},
    {0xab3033c9,0xc0e3,0x4759,{0x93,0x7d,0x57,0x58,0xc6,0x5d,0x4a,0xe3}},
    {0x4ebf7562,0x9f18,0x4d06,{0x99,0x41,0xa7,0xa6,0x25,0x74,0x4d,0x71}},
    {0xcdfe6aab,0xc083,0x4142,{0x86,0x79,0xc0,0x8f,0x95,0x32,0x9c,0x61}},
    {0xd7ff9a56,0xcdaa,0x472b,{0x84,0xdb,0xd2,0x39,0x63,0xc1,0xd1,0xbf}},
};

static int is_profile_field(const GUID* g)
{
    int i;
    for (i = 0; i < 5; i++)
        if (guid_eq(g, &g_profile_keys[i])) return 1;
    return 0;
}

static void profile_name(unsigned int p, char* out, size_t outn)
{
    (void)outn;
    out[0] = 0;
    if (p & 1u) strcat(out, "域");
    if (p & 2u) { if (out[0]) strcat(out, ", "); strcat(out, "专用"); }
    if (p & 4u) { if (out[0]) strcat(out, ", "); strcat(out, "公用"); }
    if (!out[0]) strcat(out, "未知");
}

static const wchar_t* field_name(const GUID* g)
{
    size_t i;
    if (guid_eq(g, &COND_IP_PROTOCOL))    return L"协议";
    if (guid_eq(g, &COND_IP_LOCAL_ADDR))  return L"本地地址";
    if (guid_eq(g, &COND_IP_REMOTE_ADDR)) return L"远程地址";
    if (guid_eq(g, &COND_IP_LOCAL_PORT))  return L"本地端口";
    if (guid_eq(g, &COND_IP_REMOTE_PORT)) return L"远程端口";
    if (guid_eq(g, &COND_ALE_APP_ID))     return L"应用程序";
    if (guid_eq(g, &COND_ALE_USER_ID))    return L"用户";
    if (guid_eq(g, &COND_IPSEC_QM_SA_ID))  return L"IPsec SA ID";
    for (i = 0; i < sizeof(g_cond_extra) / sizeof(g_cond_extra[0]); i++)
        if (guid_eq(g, &g_cond_extra[i].key)) return g_cond_extra[i].name;
    return NULL;
}

static const char* match_name(unsigned int m)
{
    switch (m)
    {
        case FWP_MATCH_EQUAL: return "=";
        case 1: return ">"; case 2: return "<"; case 3: return ">="; case 4: return "<=";
        case FWP_MATCH_RANGE: return "在范围内";
        case 6: return "标志全为1"; case 7: return "标志任一为1"; case 8: return "标志全为0";
        case 9: return "等于(忽略大小写)"; case 10: return "!="; case 11: return "前缀";
        default: return "?";
    }
}

static const char* type_name(unsigned int t)
{
    switch (t)
    {
        case FWP_UINT8:  return "UINT8";
        case FWP_UINT16: return "UINT16";
        case FWP_UINT32: return "UINT32";
        case FWP_INT8:   return "INT8";
        case FWP_INT16:  return "INT16";
        case FWP_INT32:  return "INT32";
        case FWP_UINT64: return "UINT64";
        case FWP_INT64:  return "INT64";
        case FWP_FLOAT: return "FLOAT";
        case FWP_DOUBLE: return "DOUBLE";
        case FWP_BYTE_ARRAY16: return "ARRAY16";
        case FWP_BYTE_BLOB:    return "BLOB";
        case FWP_SECURITY_DESC: return "SD";
        case FWP_SID:    return "SID";
        case FWP_UNICODE_STRING: return "UNISTR";
        case FWP_V4_ADDR_MASK: return "V4MASK";
        case FWP_V6_ADDR_MASK: return "V6MASK";
        case FWP_RANGE_TYPE:   return "RANGE";
        case FWP_EMPTY:   return "EMPTY";
        default: return "?";
    }
}

/* 网络字节序数值 (0xAABBCCDD) → 点分 IP */
static void fmt_ip4(unsigned int a, char* out, size_t outn)
{
    _snprintf(out, outn, "%u.%u.%u.%u",
              (a >> 24) & 0xFFu, (a >> 16) & 0xFFu,
              (a >> 8) & 0xFFu, a & 0xFFu);
}

/* 渲染单个 W_VALUE0 → UTF-8 文本 (out 由调用方提供) */
static void render_value(const W_VALUE0* v, int is_port, int is_addr, char* out, size_t outn)
{
    struct in_addr ia;
    char ipbuf[64];
    out[0] = 0;
    if (!v) { _snprintf(out, outn, "<无条件>"); return; }
    switch (v->type)
    {
        case FWP_UINT8:
            if (v->value.uint8 == 1 || v->value.uint8 == 6 || v->value.uint8 == 17 ||
                v->value.uint8 == 47 || v->value.uint8 == 58)
                _snprintf(out, outn, "%s", proto_name(v->value.uint8));
            else
                _snprintf(out, outn, "%u", v->value.uint8);
            break;
        case FWP_UINT16:
            _snprintf(out, outn, "%u", v->value.uint16);
            break;
        case FWP_UINT32:
            if (is_addr)
            {
                char ip[48];
                fmt_ip4(v->value.uint32, ip, sizeof(ip));
                _snprintf(out, outn, "%s", ip);
            }
            else
                _snprintf(out, outn, "%u", v->value.uint32);
            break;
        case FWP_UINT64:
        case FWP_INT64:
            if (v->value.ptr)
                _snprintf(out, outn, "%llu", *(unsigned long long*)v->value.ptr);
            break;
        case FWP_FLOAT:
            _snprintf(out, outn, "%g", v->value.float32);
            break;
        case FWP_DOUBLE:
            if (v->value.ptr) _snprintf(out, outn, "%g", *(double*)v->value.ptr);
            break;
        case FWP_BYTE_ARRAY16:
            if (v->value.ptr)
            {
                struct in6_addr a6;
                memcpy(&a6, v->value.ptr, 16);
                inet_ntop(AF_INET6, &a6, ipbuf, sizeof(ipbuf));
                _snprintf(out, outn, "%s", ipbuf);
            }
            break;
        case FWP_BYTE_BLOB:
        {
            W_BYTE_BLOB* b = (W_BYTE_BLOB*)v->value.ptr;
            if (b && b->size && b->data)
            {
                unsigned char* raw = (unsigned char*)b->data;
                if ((b->size & 1) == 0)
                {
                    wchar_t* w = (wchar_t*)malloc(b->size + 2);
                    if (w)
                    {
                        char* u;
                        memcpy(w, raw, b->size);
                        w[b->size / 2] = 0;
                        u = w2u(w);
                        if (u) { _snprintf(out, outn, "%s", u); free(u); }
                        free(w);
                    }
                }
                if (!out[0]) _snprintf(out, outn, "<数据 %u 字节>", b->size);
            }
            else _snprintf(out, outn, "<空>");
            break;
        }
        case FWP_SECURITY_DESC:
        {
            /* 将 SD 字节转换为 SDDL 字符串 */
            W_BYTE_BLOB* bb = (W_BYTE_BLOB*)v->value.ptr;
            if (bb && bb->size > 0 && bb->data)
            {
                wchar_t* sddl = NULL;
                if (pConvertSDtoSDR(bb->data, 1, 7, &sddl, NULL) && sddl)
                {
                    char* u = w2u(sddl);
                    _snprintf(out, outn, "%s", u ? u : "?");
                    if (u) free(u);
                    pLocalFree(sddl);
                    break;
                }
            }
            _snprintf(out, outn, "<安全描述符>");
            break;
        }
        case FWP_SID:
            if (pConvertSidToStringSidW && v->value.ptr)
            {
                wchar_t* s = NULL;
                if (pConvertSidToStringSidW(v->value.ptr, &s) && s)
                {
                    char* u = w2u(s);
                    if (u) { _snprintf(out, outn, "%s", u); free(u); }
                    if (pLocalFree) pLocalFree(s);
                }
                if (!out[0]) _snprintf(out, outn, "<SID>");
            }
            else _snprintf(out, outn, "<SID>");
            break;
        case FWP_V4_ADDR_MASK:
        {
            W_V4_ADDR_AND_MASK* m = (W_V4_ADDR_AND_MASK*)v->value.ptr;
            if (m)
            {
                /* addr/mask 为网络字节序数值: 逐字节取最高位 → 0xAABBCCDD 即 A.B.C.D */
                unsigned int a = m->addr;
                char abuf[48];
                int pfx = popcount32(m->mask);
                _snprintf(abuf, sizeof(abuf), "%u.%u.%u.%u",
                          (a >> 24) & 0xFFu, (a >> 16) & 0xFFu,
                          (a >> 8) & 0xFFu, a & 0xFFu);
                if (pfx == 32) _snprintf(out, outn, "%s", abuf);
                else _snprintf(out, outn, "%s/%d", abuf, pfx);
            }
            break;
        }
        case FWP_V6_ADDR_MASK:
        {
            W_V6_ADDR_AND_MASK* m = (W_V6_ADDR_AND_MASK*)v->value.ptr;
            if (m)
            {
                struct in6_addr a6;
                memcpy(&a6, m->addr, 16);
                inet_ntop(AF_INET6, &a6, ipbuf, sizeof(ipbuf));
                if (m->prefixLength == 128) _snprintf(out, outn, "%s", ipbuf);
                else _snprintf(out, outn, "%s/%d", ipbuf, m->prefixLength);
            }
            break;
        }
        case FWP_RANGE_TYPE:
        {
            W_RANGE0* r = (W_RANGE0*)v->value.ptr;
            if (r)
            {
                /* 地址范围且两端均为 UINT32: 对齐单个 CIDR 块显示 "ip/prefix", 否则 "ip1 ~ ip2" */
                if (is_addr && !is_port &&
                    r->low.type == FWP_UINT32 && r->high.type == FWP_UINT32)
                {
                    unsigned int l = r->low.value.uint32;
                    unsigned int h = r->high.value.uint32;
                    if (l <= h)
                    {
                        unsigned int diff = h - l + 1;
                        char abuf[48], bbuf[48];
                        fmt_ip4(l, abuf, sizeof(abuf));
                        if ((diff & (diff - 1)) == 0 && (l & (diff - 1)) == 0)
                        {
                            int prefix = 32;
                            unsigned int d = diff;
                            while (d > 1) { d >>= 1; prefix--; }
                            _snprintf(out, outn, "%s/%d", abuf, prefix);
                            break;
                        }
                        fmt_ip4(h, bbuf, sizeof(bbuf));
                        _snprintf(out, outn, "%s ~ %s", abuf, bbuf);
                        break;
                    }
                }
                {
                    char lo[64], hi[64];
                    render_value(&r->low, is_port, is_addr, lo, sizeof(lo));
                    render_value(&r->high, is_port, is_addr, hi, sizeof(hi));
                    _snprintf(out, outn, "%s ~ %s", lo, hi);
                }
            }
            break;
        }
        case FWP_EMPTY:
            _snprintf(out, outn, "<无条件>");
            break;
        default:
            _snprintf(out, outn, "(类型 %u)", v->type);
            break;
    }
}

static const char* action_name(unsigned int a, int long_form)
{
    if (a == FWP_ACTION_BLOCK)  return long_form ? "BLOCK (阻断)" : "BLOCK";
    if (a == FWP_ACTION_PERMIT) return long_form ? "PERMIT (放行)" : "PERMIT";
    if (a & 0x00004000u) return "CALLOUT";
    return "?";
}

static void flags_str(unsigned int flags, char* out)
{
    out[0] = 0;
    if (flags & WF_FLAG_PERSISTENT) strcat(out, "P");
    if (flags & WF_FLAG_BOOTTIME)   strcat(out, "B");
    if (flags & WF_FLAG_DISABLED)   strcat(out, "D");
    if (flags & WF_FLAG_INDEXED)    strcat(out, "I");
    if (!out[0]) strcpy(out, "-");
}

/* ==========================================================================
 * 命令: layers / sublayers
 * ======================================================================== */
static int cmd_layers(void)
{
    WENGINE h;
    void* enumh = NULL;
    long hr;
    if (!engine_open(&h)) return 1;
    hr = pFwpmLayerCreateEnumHandle0(h, NULL, &enumh);
    if (hr != 0) { engine_close(h); return g_err("创建层枚举句柄", hr); }
    {
        int total = 0;
        printf("\n本机 WFP 过滤层:\n");
        printf("----------------------------------------------------------------------\n");
        for (;;)
        {
            void** entries = NULL;
            unsigned int count = 0;
            hr = pFwpmLayerEnum0(h, enumh, 512, &entries, &count);
            if (hr != 0) { pFwpmLayerDestroyEnumHandle0(h, enumh); engine_close(h); return g_err("枚举层", hr); }
            if (count == 0) { if (entries) pFwpmFreeMemory0((void**)&entries); break; }
            {
                unsigned int i;
                for (i = 0; i < count; i++)
                {
                    W_LAYER0* l = (W_LAYER0*)entries[i];
                    char gbuf[48];
                    const wchar_t* alias = layer_alias_of(&l->layerKey);
                    char* nm = w2u(l->displayData.name ? l->displayData.name : L"<无名>");
                    fmt_guid(&l->layerKey, gbuf, 48);
                    printf("%-34s {%s}%s\n", nm ? nm : "?", gbuf,
                           alias ? "  <-- 可用别名" : "");
                    if (nm) free(nm);
                    total++;
                }
            }
            pFwpmFreeMemory0((void**)&entries);
            if (count < 512) break;
        }
        printf("----------------------------------------------------------------------\n");
        printf("共 %d 个\n", total);
    }
    pFwpmLayerDestroyEnumHandle0(h, enumh);
    engine_close(h);
    return 0;
}

static int cmd_sublayers(void)
{
    WENGINE h;
    void* enumh = NULL;
    long hr;
    if (!engine_open(&h)) return 1;
    hr = pFwpmSubLayerCreateEnumHandle0(h, NULL, &enumh);
    if (hr != 0) { engine_close(h); return g_err("创建子层枚举句柄", hr); }
    {
        int total = 0;
        printf("\n本机 WFP 子层:\n");
        printf("----------------------------------------------------------------------\n");
        for (;;)
        {
            void** entries = NULL;
            unsigned int count = 0;
            hr = pFwpmSubLayerEnum0(h, enumh, 512, &entries, &count);
            if (hr != 0) { pFwpmSubLayerDestroyEnumHandle0(h, enumh); engine_close(h); return g_err("枚举子层", hr); }
            if (count == 0) { if (entries) pFwpmFreeMemory0((void**)&entries); break; }
            {
                unsigned int i;
                for (i = 0; i < count; i++)
                {
                    W_SUB_LAYER0* s = (W_SUB_LAYER0*)entries[i];
                    char gbuf[48];
                    char* nm = w2u(s->displayData.name ? s->displayData.name : L"<无名>");
                    fmt_guid(&s->subLayerKey, gbuf, 48);
                    printf("权重 %04X  %-30s {%s}%s\n", s->weight, nm ? nm : "?", gbuf,
                           guid_eq(&s->subLayerKey, &WFPCTL_SUBLAYER) ? "   [本工具默认子层]" : "");
                    if (nm) free(nm);
                    total++;
                }
            }
            pFwpmFreeMemory0((void**)&entries);
            if (count < 512) break;
        }
        printf("----------------------------------------------------------------------\n");
        printf("共 %d 个\n", total);
    }
    pFwpmSubLayerDestroyEnumHandle0(h, enumh);
    engine_close(h);
    return 0;
}

/* ==========================================================================
 * 命令: list / show / del
 * ======================================================================== */
static int cmd_list(int argc, wchar_t** argv, int argbase)
{
    int show_all = 0, i;
    GUID layer_filter;
    int has_layer_filter = 0;
    GUID sublayer_filter;
    int has_sublayer_filter = 0;
    const wchar_t* sublayer_name = NULL;   /* 按名称匹配时暂存, 引擎打开后解析 */
    GUID sublayer_set[64];
    int sublayer_set_n = 0;
    int action_filter = 0;          /* 0=不过滤 1=BLOCK 2=PERMIT */
    const wchar_t* name_filter = NULL;
    WENGINE h;
    void* enumh = NULL;
    long hr;

    memset(&layer_filter, 0, sizeof(layer_filter));
    memset(&sublayer_filter, 0, sizeof(sublayer_filter));
    for (i = argbase; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--all") == 0) show_all = 1;
        else if (wcscmp(argv[i], L"--name") == 0 && i + 1 < argc) name_filter = argv[++i];
        else if (wcscmp(argv[i], L"--action") == 0 && i + 1 < argc)
        {
            wchar_t* a = argv[++i];
            if (wcscmp(a, L"block") == 0) action_filter = 1;
            else if (wcscmp(a, L"permit") == 0 || wcscmp(a, L"allow") == 0) action_filter = 2;
            else { fprintf(stderr, "list: --action 仅支持 block 或 permit。\n"); return 1; }
        }
        else if (wcscmp(argv[i], L"--layer") == 0 && i + 1 < argc)
        {
            if (!resolve_layer(argv[++i], &layer_filter))
            { char* u = w2u(argv[i]); fprintf(stderr, "list: 无法识别的层: %s\n", u ? u : "?"); free(u); return 1; }
            has_layer_filter = 1;
        }
        else if (wcscmp(argv[i], L"--sublayer") == 0 && i + 1 < argc)
        {
            if (wcscmp(argv[++i], L"default") == 0) sublayer_filter = WFPCTL_SUBLAYER;
            else if (!parse_guid(argv[i], &sublayer_filter))
            {
                /* 不是 GUID → 视为子层名称, 引擎打开后枚举匹配 */
                if (!*argv[i])
                { fprintf(stderr, "list: --sublayer 需要子层 GUID、名称或 default。\n"); return 1; }
                sublayer_name = argv[i];
            }
            has_sublayer_filter = 1;
        }
        else { char* u = w2u(argv[i]); fprintf(stderr, "list: 无法识别的参数 %s\n", u ? u : "?"); free(u); return 1; }
    }

    if (!engine_open(&h)) return 1;

    /* --sublayer 传的是名称时: 枚举子层做大小写不敏感子串匹配 */
    if (sublayer_name)
    {
        void* senumh = NULL;
        long shr = pFwpmSubLayerCreateEnumHandle0(h, NULL, &senumh);
        if (shr != 0) { engine_close(h); return g_err("创建子层枚举句柄", shr); }
        for (;;)
        {
            void** entries = NULL;
            unsigned int count = 0;
            shr = pFwpmSubLayerEnum0(h, senumh, 512, &entries, &count);
            if (shr != 0) { pFwpmSubLayerDestroyEnumHandle0(h, senumh); engine_close(h); return g_err("枚举子层", shr); }
            if (count == 0) { if (entries) pFwpmFreeMemory0((void**)&entries); break; }
            {
                unsigned int k;
                for (k = 0; k < count; k++)
                {
                    W_SUB_LAYER0* s = (W_SUB_LAYER0*)entries[k];
                    if (s->displayData.name && wcasestr(s->displayData.name, sublayer_name) &&
                        sublayer_set_n < 64)
                        sublayer_set[sublayer_set_n++] = s->subLayerKey;
                }
            }
            pFwpmFreeMemory0((void**)&entries);
            if (count < 512) break;
        }
        pFwpmSubLayerDestroyEnumHandle0(h, senumh);
        if (sublayer_set_n == 0)
        {
            char* u = w2u(sublayer_name);
            fprintf(stderr, "list: 未找到名称含 \"%s\" 的子层。可用 \"wfpctl_c sublayers\" 查看全部子层及其 GUID。\n", u ? u : "?");
            free(u);
            engine_close(h);
            return 1;
        }
    }

    hr = pFwpmFilterCreateEnumHandle0(h, NULL, &enumh);
    if (hr != 0) { engine_close(h); return g_err("创建过滤器枚举句柄", hr); }
    {
        long shown = 0, total = 0;
        if (sublayer_set_n > 1)
        {
            char* u = w2u(sublayer_name);
            printf("按子层名称 \"%s\" 匹配到 %d 个子层:\n", u ? u : "?", sublayer_set_n);
            free(u);
        }
        printf("\n%-12s%-10s%-16s%-8s%s\n", "ID", "动作", "层", "标志", "名称");
        printf("------------------------------------------------------------------------------\n");
        for (;;)
        {
            void** entries = NULL;
            unsigned int count = 0;
            hr = pFwpmFilterEnum0(h, enumh, 512, &entries, &count);
            if (hr != 0) { pFwpmFilterDestroyEnumHandle0(h, enumh); engine_close(h); return g_err("枚举过滤器", hr); }
            if (count == 0) { if (entries) pFwpmFreeMemory0((void**)&entries); break; }
            {
                unsigned int k;
                for (k = 0; k < count; k++)
                {
                    W_FILTER0* f = (W_FILTER0*)entries[k];
                    char lname[32];
                    char flstr[8];
                    const wchar_t* alias = layer_alias_of(&f->layerKey);
                    total++;
                    if (has_sublayer_filter)
                    {
                        if (sublayer_set_n > 0)
                        {
                            int m = 0, mi;
                            for (mi = 0; mi < sublayer_set_n; mi++)
                                if (guid_eq(&f->subLayerKey, &sublayer_set[mi])) { m = 1; break; }
                            if (!m) continue;
                        }
                        else if (!guid_eq(&f->subLayerKey, &sublayer_filter)) continue;
                    }
                    else if (!show_all && !guid_eq(&f->subLayerKey, &WFPCTL_SUBLAYER)) continue;
                    if (has_layer_filter && !guid_eq(&f->layerKey, &layer_filter)) continue;
                    if (action_filter == 1 && f->action.type != FWP_ACTION_BLOCK) continue;
                    if (action_filter == 2 && f->action.type != FWP_ACTION_PERMIT) continue;
                    if (name_filter &&
                        !wcasestr(f->displayData.name, name_filter) &&
                        !wcasestr(f->displayData.description, name_filter)) continue;
                    shown++;
                    if (alias) { char* a = w2u(alias); _snprintf(lname, sizeof(lname), "%s", a ? a : "?"); if (a) free(a); }
                    else { char g[48]; fmt_guid(&f->layerKey, g, 48); _snprintf(lname, sizeof(lname), "%s..", g); }
                    flags_str(f->flags, flstr);
                    {
                        char* nm = w2u(f->displayData.name ? f->displayData.name : L"<无名>");
                        printf("%-12llu%-10s%-16s%-8s%s\n", f->filterId,
                               action_name(f->action.type, 0), lname, flstr,
                               nm ? nm : "?");
                        if (nm) free(nm);
                    }
                }
            }
            pFwpmFreeMemory0((void**)&entries);
            if (count < 512) break;
        }
        printf("------------------------------------------------------------------------------\n");
        if (show_all || name_filter || action_filter || has_sublayer_filter)
            printf("共 %ld 条规则 (系统全部), 匹配显示 %ld 条\n", total, shown);
        else
            printf("共 %ld 条规则 (系统全部), 本工具创建 %ld 条。加 --all 查看系统全部规则\n", total, shown);
    }
    pFwpmFilterDestroyEnumHandle0(h, enumh);
    engine_close(h);
    return 0;
}

static int cmd_show(unsigned long long fid)
{
    WENGINE h;
    void* p = NULL;
    long hr;
    W_FILTER0* f;
    char gbuf[48];

    if (!engine_open(&h)) return 1;
    hr = pFwpmFilterGetById0(h, fid, &p);
    if (hr != 0)
    {
        if ((unsigned int)hr == 0x80320003u)
            fprintf(stderr, "show: 未找到 ID 为 %llu 的规则。\n", fid);
        else
            g_err("获取规则 (FwpmFilterGetById0)", hr);
        engine_close(h);
        return 1;
    }
    f = (W_FILTER0*)p;
    printf("\n规则 ID        : %llu\n", f->filterId);
    fmt_guid(&f->filterKey, gbuf, 48);
    printf("规则 Key       : {%s}\n", gbuf);
    { char* nm = w2u(f->displayData.name); printf("名称           : %s\n", nm ? nm : ""); if (nm) free(nm); }
    { char* ds = w2u(f->displayData.description); printf("描述           : %s\n", ds ? ds : ""); if (ds) free(ds); }
    if (f->providerKey)
    { fmt_guid(f->providerKey, gbuf, 48); printf("提供者         : {%s}\n", gbuf); }
    fmt_guid(&f->layerKey, gbuf, 48);
    printf("层             : {%s}", gbuf);
    {
        const wchar_t* alias = layer_alias_of(&f->layerKey);
        if (alias) { char* a = w2u(alias); printf("  别名 %s", a ? a : "?"); if (a) free(a); }
    }
    printf("\n");
    fmt_guid(&f->subLayerKey, gbuf, 48);
    printf("子层           : {%s}%s\n", gbuf,
           guid_eq(&f->subLayerKey, &WFPCTL_SUBLAYER) ? "  (wfpctl rules)" : "");
    printf("标志           : 0x%X%s%s%s%s\n", f->flags,
           (f->flags & WF_FLAG_PERSISTENT) ? "  [持久]" : "",
           (f->flags & WF_FLAG_BOOTTIME) ? "  [启动时]" : "",
           (f->flags & WF_FLAG_DISABLED) ? "  [已禁用]" : "",
           (f->flags & 0x40) ? "  [已索引]" : "");
    if (f->flags & WF_FLAG_BOOTTIME)
        printf("持久化         : 是 (启动时, BFE 启动阶段即生效, 重启后仍在)\n");
    else if (f->flags & WF_FLAG_PERSISTENT)
        printf("持久化         : 是 (重启后仍生效)\n");
    else if (guid_eq(&f->subLayerKey, &WFPCTL_SUBLAYER))
        printf("持久化         : 否 (临时规则, BFE 服务重启后消失)\n");
    else
        printf("持久化         : 否 (非持久, 但系统/外部服务规则, 如 Windows 防火墙规则, 其服务启动时自动重建)\n");
    printf("动作           : %s\n", action_name(f->action.type, 1));
    if (f->weight.type == FWP_EMPTY) printf("权重           : 自动");
    else
    {
        char wtxt[64];
        render_value(&f->weight, 0, 0, wtxt, sizeof(wtxt));
        printf("权重           : %s", wtxt);
    }
    if (f->effectiveWeight.type == FWP_UINT64 && f->effectiveWeight.value.ptr)
        printf("  (生效权重 0x%016llX, 同子层内值大者优先评估)",
               *(unsigned long long*)f->effectiveWeight.value.ptr);
    printf("\n");
    printf("匹配条件       : %u 个%s\n", f->numFilterConditions,
           f->numFilterConditions ? "" : " (匹配全部流量)");
    if (f->numFilterConditions && f->filterCondition)
    {
        unsigned int i;
        for (i = 0; i < f->numFilterConditions; i++)
        {
            W_FILTER_CONDITION0* c = &f->filterCondition[i];
            char g[48];
            char fnu[64];
            char vtxt[256];
            const wchar_t* fn = field_name(&c->fieldKey);
            int is_port = guid_eq(&c->fieldKey, &COND_IP_LOCAL_PORT) ||
                          guid_eq(&c->fieldKey, &COND_IP_REMOTE_PORT);
            int is_addr = guid_eq(&c->fieldKey, &COND_IP_LOCAL_ADDR) ||
                          guid_eq(&c->fieldKey, &COND_IP_REMOTE_ADDR);
            if (is_profile_field(&c->fieldKey) && c->conditionValue.type == FWP_UINT32)
            {
                char pn[32];
                profile_name(c->conditionValue.value.uint32, pn, sizeof(pn));
                _snprintf(vtxt, sizeof(vtxt), "%u (%s)", c->conditionValue.value.uint32, pn);
            }
            else
                render_value(&c->conditionValue, is_port, is_addr, vtxt, sizeof(vtxt));
            fmt_guid(&c->fieldKey, g, 48);
            if (fn) { char* u = w2u(fn); _snprintf(fnu, sizeof(fnu), "%s", u ? u : "?"); if (u) free(u); }
            else { strncpy(fnu, g, sizeof(fnu) - 1); fnu[sizeof(fnu) - 1] = 0; }
            printf("  [%u] %-10s %s  %-7s %s\n", i + 1, fnu,
                   match_name(c->matchType), type_name(c->conditionValue.type), vtxt);
        }
    }
    printf("\n");
    pFwpmFreeMemory0(&p);
    engine_close(h);
    return 0;
}

/* ================== dump ================== */
/* 命令行参数值: 含空格/引号时用双引号包裹 (内部引号转单引号) */
static void print_q(const wchar_t* s)
{
    char* u = w2u(s);
    const char* p;
    int need = 0;
    if (!u) return;
    for (p = u; *p; p++) if (*p == ' ' || *p == '\t' || *p == '"') { need = 1; break; }
    if (need) putchar('"');
    for (p = u; *p; p++) putchar(*p == '"' ? '\'' : *p);
    if (need) putchar('"');
    free(u);
}

/* 条件 → add 参数 (name/val 宽串); 无法还原时返回 0 并写 note */
static int dump_cond_arg(const W_FILTER_CONDITION0* c, wchar_t* name, size_t nsz,
                         wchar_t* val, size_t vsz, wchar_t* note, size_t notsz)
{
    const W_VALUE0* v = &c->conditionValue;
    name[0] = val[0] = note[0] = 0;
    if (guid_eq(&c->fieldKey, &COND_IP_PROTOCOL))
    {
        if (c->matchType != FWP_MATCH_EQUAL || v->type != FWP_UINT8)
        { swprintf(note, notsz, L"协议条件无法还原"); return 0; }
        swprintf(name, nsz, L"--protocol");
        swprintf(val, vsz, L"%hs", proto_name(v->value.uint8));
        return 1;
    }
    if (guid_eq(&c->fieldKey, &COND_IP_LOCAL_PORT) || guid_eq(&c->fieldKey, &COND_IP_REMOTE_PORT))
    {
        swprintf(name, nsz, L"%ls",
                 guid_eq(&c->fieldKey, &COND_IP_LOCAL_PORT) ? L"--lport" : L"--rport");
        if (c->matchType == FWP_MATCH_EQUAL && v->type == FWP_UINT16)
        { swprintf(val, vsz, L"%u", v->value.uint16); return 1; }
        if (c->matchType == FWP_MATCH_RANGE && v->type == FWP_RANGE_TYPE && v->value.ptr)
        {
            W_RANGE0* r = (W_RANGE0*)v->value.ptr;
            if (r->low.type == FWP_UINT16 && r->high.type == FWP_UINT16)
            { swprintf(val, vsz, L"%u-%u", r->low.value.uint16, r->high.value.uint16); return 1; }
        }
        swprintf(note, notsz, L"端口条件无法还原"); return 0;
    }
    if (guid_eq(&c->fieldKey, &COND_IP_LOCAL_ADDR) || guid_eq(&c->fieldKey, &COND_IP_REMOTE_ADDR))
    {
        swprintf(name, nsz, L"%ls",
                 guid_eq(&c->fieldKey, &COND_IP_LOCAL_ADDR) ? L"--lip" : L"--rip");
        if (c->matchType == FWP_MATCH_EQUAL && v->type == FWP_V4_ADDR_MASK && v->value.ptr)
        {
            W_V4_ADDR_AND_MASK* m = (W_V4_ADDR_AND_MASK*)v->value.ptr;
            char ip[48];
            int pfx = popcount32(m->mask);
            fmt_ip4(m->addr, ip, sizeof(ip));
            if (pfx == 32) swprintf(val, vsz, L"%hs", ip);
            else swprintf(val, vsz, L"%hs/%d", ip, pfx);
            return 1;
        }
        if (c->matchType == FWP_MATCH_EQUAL && v->type == FWP_UINT32)
        {
            char ip[48];
            fmt_ip4(v->value.uint32, ip, sizeof(ip));
            swprintf(val, vsz, L"%hs", ip);
            return 1;
        }
        if (c->matchType == FWP_MATCH_EQUAL && v->type == FWP_V6_ADDR_MASK && v->value.ptr)
        {
            W_V6_ADDR_AND_MASK* m = (W_V6_ADDR_AND_MASK*)v->value.ptr;
            char ipbuf[64];
            if (inet_ntop(AF_INET6, m->addr, ipbuf, sizeof(ipbuf)))
            {
                if (m->prefixLength == 128) swprintf(val, vsz, L"%hs", ipbuf);
                else swprintf(val, vsz, L"%hs/%u", ipbuf, (unsigned)m->prefixLength);
                return 1;
            }
        }
        if (c->matchType == FWP_MATCH_RANGE && v->type == FWP_RANGE_TYPE && v->value.ptr)
        {
            W_RANGE0* r = (W_RANGE0*)v->value.ptr;
            if (r->low.type == FWP_UINT32 && r->high.type == FWP_UINT32)
            {
                unsigned int l = r->low.value.uint32, h = r->high.value.uint32;
                if (l <= h)
                {
                    unsigned int diff = h - l + 1;
                    if ((diff & (diff - 1)) == 0 && (l & (diff - 1)) == 0)
                    {
                        char ip[48];
                        int prefix = 32;
                        unsigned int d = diff;
                        while (d > 1) { d >>= 1; prefix--; }
                        fmt_ip4(l, ip, sizeof(ip));
                        swprintf(val, vsz, L"%hs/%d", ip, prefix);
                        return 1;
                    }
                    {
                        char la[48], ha[48];
                        fmt_ip4(l, la, sizeof(la));
                        fmt_ip4(h, ha, sizeof(ha));
                        swprintf(note, notsz, L"地址范围 %hs ~ %hs 不对齐网段, add 无法精确还原", la, ha);
                    }
                    return 0;
                }
            }
        }
        swprintf(note, notsz, L"地址条件无法还原"); return 0;
    }
    if (guid_eq(&c->fieldKey, &COND_ALE_APP_ID))
    {
        if (c->matchType == FWP_MATCH_EQUAL && v->type == FWP_BYTE_BLOB && v->value.ptr)
        {
            W_BYTE_BLOB* b = (W_BYTE_BLOB*)v->value.ptr;
            if (b && b->size && b->data)
            {
                wchar_t* p = (wchar_t*)b->data;
                size_t maxw = b->size / 2, len = 0, i;
                int ok;
                while (len < maxw && p[len]) len++;
                ok = (len > 0) ? 1 : 0;
                for (i = 0; i < len; i++)
                    if (p[i] == 0 || (p[i] < 32 && p[i] != L'\t')) { ok = 0; break; }
                if (ok)
                {
                    swprintf(name, nsz, L"--app");
                    swprintf(val, vsz, L"%ls", p);
                    return 1;
                }
            }
        }
        swprintf(note, notsz, L"应用条件无法还原为路径"); return 0;
    }
{
        char g[48];
        wchar_t gw[64];
        const wchar_t* fn = field_name(&c->fieldKey);
        if (fn)
        {
            _snwprintf(gw, 64, L"%ls", fn);
        }
        else
        {
            fmt_guid(&c->fieldKey, g, 48);
            swprintf(gw, 64, L"{%hs}", g);
        }
        swprintf(note, notsz, L"字段 %ls 无法还原", gw);
    }
    return 0;
}

static void dump_filter(const W_FILTER0* f)
{
    char gbuf[48];
    GUID done[8];
    int done_n = 0;
    unsigned int i;
    int printed_note = 0;

    printf("\n");
    fmt_guid(&f->filterKey, gbuf, 48);
    { char* nm = w2u(f->displayData.name); printf("# 规则 ID: %llu  名称: %s  Key: {%s}\n", f->filterId, nm ? nm : "", gbuf); if (nm) free(nm); }
    printf("# 复制下面命令执行即可创建等价规则, 修改参数可快速生成新规则:\n");
    if (f->action.type != FWP_ACTION_BLOCK && f->action.type != FWP_ACTION_PERMIT)
    {
        printf("# 无法还原: 动作类型 0x%X 不是 BLOCK/PERMIT, add 不支持。\n", f->action.type);
        return;
    }
    printf("wfpctl add --action %s", f->action.type == FWP_ACTION_BLOCK ? "block" : "permit");
    if (f->displayData.name && f->displayData.name[0]) { printf(" --name "); print_q(f->displayData.name); }
    if (f->displayData.description && f->displayData.description[0]) { printf(" --desc "); print_q(f->displayData.description); }
    {
        const wchar_t* alias = layer_alias_of(&f->layerKey);
        if (alias) { char* a = w2u(alias); printf(" --layer %s", a ? a : "?"); if (a) free(a); }
        else { fmt_guid(&f->layerKey, gbuf, 48); printf(" --layer {%s}", gbuf); }
    }
    if (!guid_eq(&f->subLayerKey, &WFPCTL_SUBLAYER))
    { fmt_guid(&f->subLayerKey, gbuf, 48); printf(" --sublayer {%s}", gbuf); }
    if (f->flags & WF_FLAG_BOOTTIME) printf(" --boottime");
    else if (!(f->flags & WF_FLAG_PERSISTENT)) printf(" --volatile");
    if (f->flags & WF_FLAG_DISABLED) printf("  # 注: 原规则为禁用状态, add 无法保留");
    if (f->weight.type == FWP_UINT8) printf(" --weight %u", f->weight.value.uint8);

    for (i = 0; i < f->numFilterConditions; i++)
    {
        W_FILTER_CONDITION0* c = &f->filterCondition[i];
        wchar_t an[16], av[200], note[200];
        int j, dup = 0;
        if (!dump_cond_arg(c, an, 16, av, 200, note, 200))
        {
            if (note[0] && !printed_note)
            {
                char* u = w2u(note);
                printf("\n# 注: %s", u ? u : "?");
                if (u) free(u);
                printed_note = 1;
            }
            continue;
        }
        int is_addr_field = guid_eq(&c->fieldKey, &COND_IP_LOCAL_ADDR) ||
                           guid_eq(&c->fieldKey, &COND_IP_REMOTE_ADDR);
        if (!is_addr_field)
        {
            for (j = 0; j < done_n; j++)
                if (guid_eq(&done[j], &c->fieldKey)) { dup = 1; break; }
            if (dup)
            {
                if (!printed_note)
                {
                    char* u = w2u(field_name(&c->fieldKey));
                    printf("\n# 注: 原规则含多个 %s 条件 (与运算), 一条命令只能还原第一个", u ? u : "?");
                    if (u) free(u);
                    printed_note = 1;
                }
                continue;
            }
            done[done_n++] = c->fieldKey;
        }
        if (wcscmp(an, L"--app") == 0) { printf(" %ls ", an); print_q(av); }
        else printf(" %ls %ls", an, av);
    }
    printf("\n# 执行后返回新规则 ID; 需管理员权限。\n");
}

static int cmd_dump(int argc, wchar_t** argv, int argbase)
{
    WENGINE h;
    long hr;
    unsigned long long fid = 0;
    int by_id = 0;
    const wchar_t* name_filter = NULL;

    if (argc == argbase + 1 && wcscmp(argv[argbase], L"--name") != 0)
    {
        fid = _wcstoui64(argv[argbase], NULL, 10);
        by_id = 1;
    }
    else if (argc == argbase + 2 && wcscmp(argv[argbase], L"--name") == 0)
        name_filter = argv[argbase + 1];
    else
    {
        fprintf(stderr, "用法: wfpctl_c dump <规则ID>   或   wfpctl_c dump --name <关键字>\n");
        return 1;
    }

    if (!engine_open(&h)) return 1;
    if (by_id)
    {
        void* p = NULL;
        W_FILTER0* f;
        hr = pFwpmFilterGetById0(h, fid, &p);
        if (hr != 0)
        {
            if ((unsigned int)hr == 0x80320003u)
                fprintf(stderr, "dump: 未找到 ID 为 %llu 的规则。\n", fid);
            else
                g_err("获取规则 (FwpmFilterGetById0)", hr);
            engine_close(h);
            return 1;
        }
        f = (W_FILTER0*)p;
        dump_filter(f);
        pFwpmFreeMemory0(&p);
        engine_close(h);
        return 0;
    }

    {
        void* enumh = NULL;
        long total = 0, shown = 0;
        hr = pFwpmFilterCreateEnumHandle0(h, NULL, &enumh);
        if (hr != 0) { engine_close(h); return g_err("创建枚举句柄", hr); }
        for (;;)
        {
            void** entries = NULL;
            unsigned int count = 0;
            unsigned int k;
            hr = pFwpmFilterEnum0(h, enumh, 512, &entries, &count);
            if (hr != 0) { pFwpmFilterDestroyEnumHandle0(h, enumh); engine_close(h); return g_err("枚举过滤器", hr); }
            if (count == 0) { if (entries) pFwpmFreeMemory0((void**)&entries); break; }
            for (k = 0; k < count; k++)
            {
                W_FILTER0* f = (W_FILTER0*)entries[k];
                total++;
                if (!wcasestr(f->displayData.name, name_filter) &&
                    !wcasestr(f->displayData.description, name_filter)) continue;
                shown++;
                dump_filter(f);
            }
            pFwpmFreeMemory0((void**)&entries);
            if (count < 512) break;
        }
        pFwpmFilterDestroyEnumHandle0(h, enumh);
        engine_close(h);
        if (shown == 0)
        {
            fprintf(stderr, "dump: 未找到匹配的规则。\n");
            return 1;
        }
    }
    return 0;
}

static int cmd_del(int argc, wchar_t** argv, int argbase)
{
    WENGINE h;
    long hr;

    if (argbase < argc && wcscmp(argv[argbase], L"--name") == 0)
    {
        const wchar_t* target;
        void* enumh = NULL;
        unsigned long long* ids = NULL;
        size_t nids = 0, cap = 0, i;
        int fail = 0;
        if (argbase + 2 != argc) { fprintf(stderr, "del: --name 后需要规则名称。\n"); return 1; }
        target = argv[argbase + 1];
        if (!engine_open(&h)) return 1;
        hr = pFwpmFilterCreateEnumHandle0(h, NULL, &enumh);
        if (hr != 0) { engine_close(h); return g_err("创建过滤器枚举句柄", hr); }
        for (;;)
        {
            void** entries = NULL;
            unsigned int count = 0;
            hr = pFwpmFilterEnum0(h, enumh, 512, &entries, &count);
            if (hr != 0) { pFwpmFilterDestroyEnumHandle0(h, enumh); engine_close(h); return g_err("枚举过滤器", hr); }
            if (count == 0) { if (entries) pFwpmFreeMemory0((void**)&entries); break; }
            {
                unsigned int k;
                for (k = 0; k < count; k++)
                {
                    W_FILTER0* f = (W_FILTER0*)entries[k];
                    if (f->displayData.name && wcscmp(f->displayData.name, target) == 0)
                    {
                        if (nids == cap)
                        {
                            cap = cap ? cap * 2 : 16;
                            ids = (unsigned long long*)realloc(ids, cap * sizeof(*ids));
                        }
                        ids[nids++] = f->filterId;
                    }
                }
            }
            pFwpmFreeMemory0((void**)&entries);
            if (count < 512) break;
        }
        pFwpmFilterDestroyEnumHandle0(h, enumh);
        if (nids == 0)
        { char* u = w2u(target); fprintf(stderr, "del: 没有找到名称为 \"%s\" 的规则。\n", u ? u : "?"); free(u); free(ids); engine_close(h); return 1; }
        for (i = 0; i < nids; i++)
        {
            hr = pFwpmFilterDeleteById0(h, ids[i]);
            if (hr != 0) { fprintf(stderr, "del: 删除 ID %llu 失败 (0x%08X)\n", ids[i], (unsigned int)hr); fail = 1; }
            else printf("已删除规则 ID = %llu\n", ids[i]);
        }
        free(ids);
        engine_close(h);
        return fail ? 1 : 0;
    }

    if (argbase + 1 != argc)
    { fprintf(stderr, "用法: wfpctl_c del <规则ID>   或   wfpctl_c del --name <规则名称>\n"); return 1; }
    {
        unsigned long long fid = _wcstoui64(argv[argbase], NULL, 10);
        if (!engine_open(&h)) return 1;
        hr = pFwpmFilterDeleteById0(h, fid);
        if (hr != 0)
        {
            if ((unsigned int)hr == 0x80320003u)
                fprintf(stderr, "del: 未找到 ID 为 %llu 的规则。\n", fid);
            else
                fprintf(stderr, "错误: 删除规则 %llu 失败: 0x%08X\n", fid, (unsigned int)hr);
            engine_close(h);
            return 1;
        }
        printf("已删除规则 ID = %llu\n", fid);
        engine_close(h);
        return 0;
    }
}

/* ==========================================================================
 * 命令: add
 * ======================================================================== */
typedef struct { int lo, hi; } PortRange;

static int parse_protocol(const wchar_t* s)
{
    if (wcscmp(s, L"tcp") == 0) return 6;
    if (wcscmp(s, L"udp") == 0) return 17;
    if (wcscmp(s, L"icmp") == 0) return 1;
    if (wcscmp(s, L"icmpv6") == 0) return 58;
    if (wcscmp(s, L"any") == 0) return -1;
    {
        wchar_t* end;
        long n = wcstol(s, &end, 10);
        if (end && *end == 0 && n >= 0 && n <= 255) return (int)n;
    }
    return -2;
}

/* 端口列表: 返回段数; *out 数组由调用方提供 (容量 16); 失败返回 -1 */
static int parse_port_list(const wchar_t* s, PortRange* out, int cap)
{
    int n = 0;
    const wchar_t* p;
    if (!s) { out[n].lo = out[n].hi = -1; return 1; }
    p = s;
    while (*p && n < cap)
    {
        int lo, hi;
        wchar_t* end;
        lo = (int)wcstol(p, &end, 10);
        if (end == p || lo < 1 || lo > 65535) return -1;
        p = end;
        if (*p == L'-')
        {
            p++;
            hi = (int)wcstol(p, &end, 10);
            if (end == p || hi < lo || hi > 65535) return -1;
            p = end;
        }
        else hi = lo;
        out[n].lo = lo; out[n].hi = hi;
        n++;
        if (*p == L',') { p++; continue; }
        if (*p) return -1;
    }
    if (*p) return -1;
    return n;
}

/* 附加内存管理: add 事务期间所有 malloc 的指针登记, 统一释放 */
#define KEEPMAX 256
typedef struct { void* ptrs[KEEPMAX]; int n; } KeepList;
static void keep_add(KeepList* k, void* p)
{
    if (k->n < KEEPMAX) k->ptrs[k->n++] = p;
}
static void keep_free_all(KeepList* k)
{
    int i;
    for (i = 0; i < k->n; i++) free(k->ptrs[i]);
    k->n = 0;
}

/* 构造一个 IP 条件 (IPv4: 8 字节 addr+mask; IPv6: 17 字节 addr+prefix) */
static int add_ip_cond(KeepList* k, W_FILTER_CONDITION0* c, const GUID* field, const wchar_t* spec)
{
    wchar_t ip[64];
    char ipa[64];
    const wchar_t* slash = wcschr(spec, L'/');
    const wchar_t* maskstr = NULL;
    int prefix = -1;

    if (slash)
    {
        size_t n = (size_t)(slash - spec);
        if (n >= 64) return 0;
        wcsncpy(ip, spec, n); ip[n] = 0;
        maskstr = slash + 1;
    }
    else wcscpy(ip, spec);

    memset(c, 0, sizeof(*c));
    c->fieldKey = *field;
    c->matchType = FWP_MATCH_EQUAL;

    /* inet_pton 是窄字符 (ANSI) 接口, 先把宽串窄化 (IP 与掩码均为 ASCII) */
    {
        size_t i;
        for (i = 0; i < 63 && ip[i]; i++) ipa[i] = (char)((unsigned)ip[i] & 0xFFu);
        ipa[i] = 0;
        if (ip[i]) return 0;
    }

    if (wcschr(ip, L':') == NULL)   /* IPv4 */
    {
        struct in_addr a4;
        unsigned int mask = 0xFFFFFFFFu;
        unsigned char* buf;
        unsigned char* pa;
        unsigned int av;
        if (inet_pton(AF_INET, ipa, &a4) != 1) return 0;
        if (maskstr)
        {
            wchar_t* end;
            prefix = (int)wcstol(maskstr, &end, 10);
            if (end && *end == 0)
            {
                if (prefix < 0 || prefix > 32) return 0;
                mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
            }
            else
            {
                struct in_addr m4;
                char mbuf[64];
                size_t i, j = 0;
                unsigned char* pm;
                for (i = 0; maskstr[i] && j < 63; i++) mbuf[j++] = (char)((unsigned)maskstr[i] & 0xFFu);
                mbuf[j] = 0;
                if (inet_pton(AF_INET, mbuf, &m4) != 1) return 0;
                /* 点分十进制掩码: inet_pton 按字节序填充, 需转成网络字节序数值 */
                pm = (unsigned char*)&m4.S_un.S_addr;
                mask = ((unsigned int)pm[0] << 24) | ((unsigned int)pm[1] << 16) |
                       ((unsigned int)pm[2] << 8) | (unsigned int)pm[3];
            }
        }
        buf = (unsigned char*)calloc(1, 8);
        if (!buf) return 0;
        keep_add(k, buf);
        /* addr 字段为网络字节序数值: inet_pton 的 4 字节 (A B C D) 转成 0xABCD 数值存储 */
        pa = (unsigned char*)&a4.S_un.S_addr;
        av = ((unsigned int)pa[0] << 24) | ((unsigned int)pa[1] << 16) |
             ((unsigned int)pa[2] << 8) | (unsigned int)pa[3];
        memcpy(buf, &av, 4);
        memcpy(buf + 4, &mask, 4);
        c->conditionValue.type = FWP_V4_ADDR_MASK;
        c->conditionValue.value.ptr = buf;
    }
    else                              /* IPv6 */
    {
        struct in6_addr a6;
        unsigned char* buf;
        if (inet_pton(AF_INET6, ipa, &a6) != 1) return 0;
        prefix = 128;
        if (maskstr)
        {
            wchar_t* end;
            prefix = (int)wcstol(maskstr, &end, 10);
            if (end != maskstr && *end == 0)
            { if (prefix < 0 || prefix > 128) return 0; }
            else return 0;
        }
        buf = (unsigned char*)calloc(1, 17);
        if (!buf) return 0;
        keep_add(k, buf);
        memcpy(buf, &a6, 16);
        buf[16] = (unsigned char)prefix;
        c->conditionValue.type = FWP_V6_ADDR_MASK;
        c->conditionValue.value.ptr = buf;
    }
    return 1;
}

static int add_port_cond(KeepList* k, W_FILTER_CONDITION0* c, const GUID* field, PortRange pr)
{
    memset(c, 0, sizeof(*c));
    c->fieldKey = *field;
    if (pr.lo == pr.hi)
    {
        c->matchType = FWP_MATCH_EQUAL;
        c->conditionValue.type = FWP_UINT16;
        c->conditionValue.value.uint16 = (unsigned short)pr.lo;
    }
    else
    {
        /* 端口范围: BFE 以主机字节序比较, low < high 即可 */
        unsigned short nlo = (unsigned short)pr.lo;
        unsigned short nhi = (unsigned short)pr.hi;
        W_RANGE0* r;
        if (nlo > nhi)
        {
            fprintf(stderr,
                "错误: 端口范围 %d-%d 无效 (起大于止)。\n",
                pr.lo, pr.hi);
            return 0;
        }
        r = (W_RANGE0*)calloc(1, sizeof(*r));
        if (!r) return 0;
        keep_add(k, r);
        r->low.type = FWP_UINT16;  r->low.value.uint16 = nlo;
        r->high.type = FWP_UINT16; r->high.value.uint16 = nhi;
        c->matchType = FWP_MATCH_RANGE;
        c->conditionValue.type = FWP_RANGE_TYPE;
        c->conditionValue.value.ptr = r;
    }
    return 1;
}

static int cmd_add(int argc, wchar_t** argv, int argbase)
{
    wchar_t* name = wdup(L"wfpctl rule");
    wchar_t* desc = wdup(L"");
    wchar_t* layerStr = wdup(L"connect-v4");
    wchar_t* sublayerStr = NULL;
    int action_block = 0;   /* 默认 permit (放行); 阻断需显式 --action block */
    int protocol = -1;
    wchar_t* lportStr = NULL, * rportStr = NULL;
    wchar_t* lips[8] = { NULL }; int lipCount = 0;
    wchar_t* rips[8] = { NULL }; int ripCount = 0;
    wchar_t* app = NULL;
    int boottime = 0, volatileFlag = 0;
    int weight = -1;
    GUID layer, sublayer;
    PortRange lports[16], rports[16];
    int nl, nr, total, i;
    WENGINE h;
    long hr;
    void* appBlob = NULL;
    KeepList keep;
    unsigned long long* added = NULL;
    int nAdded = 0;
    int ret = 1;

    keep.n = 0;
    for (i = argbase; i < argc; i++)
    {
        wchar_t* a = argv[i];
        if (wcscmp(a, L"--name") == 0 && i + 1 < argc) { free(name); name = wdup(argv[++i]); }
        else if (wcscmp(a, L"--desc") == 0 && i + 1 < argc) { free(desc); desc = wdup(argv[++i]); }
        else if (wcscmp(a, L"--layer") == 0 && i + 1 < argc) { free(layerStr); layerStr = wdup(argv[++i]); }
        else if (wcscmp(a, L"--sublayer") == 0 && i + 1 < argc) { free(sublayerStr); sublayerStr = wdup(argv[++i]); }
        else if (wcscmp(a, L"--action") == 0 && i + 1 < argc)
        {
            wchar_t* act = argv[++i];
            if (wcscmp(act, L"block") == 0) action_block = 1;
            else if (wcscmp(act, L"permit") == 0 || wcscmp(act, L"allow") == 0) action_block = 0;
            else { fprintf(stderr, "add: --action 仅支持 block 或 permit。\n"); goto done; }
        }
        else if (wcscmp(a, L"--protocol") == 0 && i + 1 < argc)
        {
            protocol = parse_protocol(argv[++i]);
            if (protocol == -2) { fprintf(stderr, "add: 无效的协议。\n"); goto done; }
        }
        else if (wcscmp(a, L"--lport") == 0 && i + 1 < argc) { free(lportStr); lportStr = wdup(argv[++i]); }
        else if (wcscmp(a, L"--rport") == 0 && i + 1 < argc) { free(rportStr); rportStr = wdup(argv[++i]); }
        else if (wcscmp(a, L"--lip") == 0 && i + 1 < argc)
        {
            if (lipCount >= 8) { fprintf(stderr, "add: --lip 参数过多 (最多 8 个)。\n"); goto done; }
            lips[lipCount++] = wdup(argv[++i]);
        }
        else if (wcscmp(a, L"--rip") == 0 && i + 1 < argc)
        {
            if (ripCount >= 8) { fprintf(stderr, "add: --rip 参数过多 (最多 8 个)。\n"); goto done; }
            rips[ripCount++] = wdup(argv[++i]);
        }
        else if (wcscmp(a, L"--app") == 0 && i + 1 < argc) { free(app); app = wdup(argv[++i]); }
        else if (wcscmp(a, L"--boottime") == 0) boottime = 1;
        else if (wcscmp(a, L"--volatile") == 0) volatileFlag = 1;
        else if (wcscmp(a, L"--weight") == 0 && i + 1 < argc)
        {
            wchar_t* end;
            weight = (int)wcstol(argv[++i], &end, 10);
            if (end == argv[i] || weight < 0 || weight > 15)
            { fprintf(stderr, "add: --weight 须为 0-15 (15 最高优先, 同子层内先评估)。缺省则由 BFE 自动分配。\n"); goto done; }
        }
        else { char* u = w2u(a); fprintf(stderr, "add: 无法识别的参数 %s\n", u ? u : "?"); free(u); goto done; }
    }

    if (!resolve_layer(layerStr, &layer))
    {
        char* u = w2u(layerStr);
        fprintf(stderr, "add: 无法识别的层 \"%s\"。可用别名:\n", u ? u : "?");
        free(u);
        { int k; for (k = 0; k < (int)(sizeof(g_layers) / sizeof(g_layers[0])); k++)
            { char* a2 = w2u(g_layers[k].alias); printf("    %-11s  %s\n", a2 ? a2 : "?", g_layers[k].desc); if (a2) free(a2); } }
        goto done;
    }

    if (!sublayerStr || wcscmp(sublayerStr, L"default") == 0) sublayer = WFPCTL_SUBLAYER;
    else if (!parse_guid(sublayerStr, &sublayer))
    { char* u = w2u(sublayerStr); fprintf(stderr, "add: 无效的子层 GUID: %s\n", u ? u : "?"); free(u); goto done; }

    nl = parse_port_list(lportStr, lports, 16);
    nr = parse_port_list(rportStr, rports, 16);
    if (nl < 0 || nr < 0)
    { fprintf(stderr, "add: 无效的端口, 应为 80 / 80-90 / 80,443 形式 (1-65535)。\n"); goto done; }
    if (!lportStr) { lports[0].lo = lports[0].hi = -1; nl = 1; }
    if (!rportStr) { rports[0].lo = rports[0].hi = -1; nr = 1; }
    total = nl * nr;
    if (total > 64)
    { fprintf(stderr, "add: 端口组合过多 (%d 条), 请分批添加。\n", total); goto done; }

    if (app)
    {
        unsigned int rc = pFwpmGetAppIdFromFileName0(app, &appBlob);
        if (rc != 0)
        { fprintf(stderr, "add: 获取应用程序 ID 失败 (0x%08X)。请确认文件路径存在。\n", rc); goto done; }
    }

    if (!engine_open(&h)) goto done;
    {
        unsigned int flags = 0;
        int seq = 0, li, ri;
        /* 注意: BOOTTIME 自身已隐含持久化, 与 PERSISTENT 组合会被 BFE 以
         * FWP_E_INVALID_FLAGS (0x8032001E) 拒绝 */
        if (boottime) flags = WF_FLAG_BOOTTIME;
        else if (!volatileFlag) flags = WF_FLAG_PERSISTENT;

        hr = pFwpmTransactionBegin0(h, 0);
        if (hr != 0) { g_err("开始事务", hr); goto close_engine; }
        added = (unsigned long long*)calloc((size_t)total, sizeof(*added));
        if (!added) { fprintf(stderr, "错误: 内存分配失败。\n"); pFwpmTransactionAbort0(h); goto close_engine; }

        hr = ensure_sublayer(h, &sublayer, TOOL_SUBLAYER_NAME, 0x100);
        if (hr != 0)
        { g_err("创建子层", hr); pFwpmTransactionAbort0(h); goto free_keep; }

        for (li = 0; li < nl; li++)
        {
            for (ri = 0; ri < nr; ri++)
            {
                W_FILTER_CONDITION0 conds[8];
                W_FILTER0 f;
                unsigned long long fid = 0;
                int nc = 0;
                wchar_t fname[256];

                seq++;
                if (total > 1) swprintf(fname, 256, L"%ls #%d", name, seq);
                else { wcsncpy(fname, name, 255); fname[255] = 0; }

                if (protocol >= 0)
                {
                    memset(&conds[nc], 0, sizeof(conds[nc]));
                    conds[nc].fieldKey = COND_IP_PROTOCOL;
                    conds[nc].matchType = FWP_MATCH_EQUAL;
                    conds[nc].conditionValue.type = FWP_UINT8;
                    conds[nc].conditionValue.value.uint8 = (unsigned char)protocol;
                    nc++;
                }
                {
                    int j;
                    for (j = 0; j < ripCount; j++)
                    {
                        if (!add_ip_cond(&keep, &conds[nc], &COND_IP_REMOTE_ADDR, rips[j]))
                        { char* u = w2u(rips[j]); pFwpmTransactionAbort0(h); fprintf(stderr, "add: 无法解析 IP 地址: %s\n", u ? u : "?"); free(u); goto free_keep; }
                        nc++;
                    }
                    for (j = 0; j < lipCount; j++)
                    {
                        if (!add_ip_cond(&keep, &conds[nc], &COND_IP_LOCAL_ADDR, lips[j]))
                        { char* u = w2u(lips[j]); pFwpmTransactionAbort0(h); fprintf(stderr, "add: 无法解析 IP 地址: %s\n", u ? u : "?"); free(u); goto free_keep; }
                        nc++;
                    }
                }
                if (lports[li].lo >= 0)
                {
                    if (!add_port_cond(&keep, &conds[nc], &COND_IP_LOCAL_PORT, lports[li]))
                    { pFwpmTransactionAbort0(h); goto free_keep; }
                    nc++;
                }
                if (rports[ri].lo >= 0)
                {
                    if (!add_port_cond(&keep, &conds[nc], &COND_IP_REMOTE_PORT, rports[ri]))
                    { pFwpmTransactionAbort0(h); goto free_keep; }
                    nc++;
                }
                if (appBlob)
                {
                    memset(&conds[nc], 0, sizeof(conds[nc]));
                    conds[nc].fieldKey = COND_ALE_APP_ID;
                    conds[nc].matchType = FWP_MATCH_EQUAL;
                    conds[nc].conditionValue.type = FWP_BYTE_BLOB;
                    conds[nc].conditionValue.value.ptr = appBlob;
                    nc++;
                }

                memset(&f, 0, sizeof(f));
                f.layerKey = layer;
                f.subLayerKey = sublayer;
                f.flags = flags;
                if (weight >= 0)
                {
                    f.weight.type = FWP_UINT8;
                    f.weight.value.uint8 = (unsigned char)weight;
                }
                f.action.type = action_block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
                f.displayData.name = fname;
                f.displayData.description = desc;
                f.numFilterConditions = (unsigned int)nc;
                f.filterCondition = conds;

                hr = pFwpmFilterAdd0(h, &f, NULL, &fid);
                if (hr != 0)
                {
                    fprintf(stderr, "错误: 添加规则 #%d 失败 (FwpmFilterAdd0): 0x%08X\n",
                             seq, (unsigned int)hr);
                    pFwpmTransactionAbort0(h);
                    goto free_keep;
                }
                added[nAdded++] = fid;
            }
        }

        hr = pFwpmTransactionCommit0(h);
        if (hr != 0)
        { g_err("提交事务", hr); pFwpmTransactionAbort0(h); goto free_keep; }

        {
            char* nm = w2u(name);
            for (i = 0; i < nAdded; i++)
                printf("已添加规则, ID = %llu  名称 = %s\n", added[i], nm ? nm : "?");
            free(nm);
        }
        if (boottime) printf("提示: 该规则为启动时间规则 (BFE 未启动时即生效)。\n");
        printf("提示: 使用 \"wfpctl_c list\" 查看, \"wfpctl_c del <ID>\" 删除。\n");
    }
    ret = 0;

free_keep:
    keep_free_all(&keep);
    if (appBlob) pFwpmFreeMemory0(&appBlob);
    free(added);
close_engine:
    engine_close(h);
done:
    free(name); free(desc); free(layerStr); free(sublayerStr);
    free(lportStr); free(rportStr); free(app);
    { int _i; for (_i = 0; _i < lipCount; _i++) free(lips[_i]); for (_i = 0; _i < ripCount; _i++) free(rips[_i]); }
    return ret;
}

/* ==========================================================================
 * 命令: update —— 修改规则 (WFP 无原地修改 API, 采用事务内"删旧+建新",
 *                  失败自动回滚; 未指定的参数保持原值)
 *   用法: wfpctl_c update <ID> [--name ..] [--desc ..] [--action ..]
 *         [--protocol ..] [--lip ..] [--rip ..] [--lport ..] [--rport ..]
 *         [--app ..] [--weight 0-15|auto] [--layer ..] [--sublayer ..]
 *         [--boottime] [--volatile] [--persistent]
 *   特殊值: any = 清除对应条件 (如 --rip any)
 * ======================================================================== */
static wchar_t* a2w(const char* s)
{
    int n;
    wchar_t* p;
    if (!s) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    p = (wchar_t*)malloc((size_t)n * sizeof(wchar_t));
    if (!p) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, p, n);
    return p;
}

/* V4/V6 地址条件 → "ip" 或 "ip/prefix" (宽串, 调用方 free) */
static wchar_t* extract_addr(const W_VALUE0* v)
{
    char cbuf[84];
    if (v->type == FWP_V4_ADDR_MASK && v->value.ptr)
    {
        W_V4_ADDR_AND_MASK* m = (W_V4_ADDR_AND_MASK*)v->value.ptr;
        unsigned int a = m->addr;
        int pfx = popcount32(m->mask);
        snprintf(cbuf, sizeof(cbuf), "%u.%u.%u.%u",
                 (a >> 24) & 0xFFu, (a >> 16) & 0xFFu,
                 (a >> 8) & 0xFFu, a & 0xFFu);
        if (pfx != 32)
        {
            char t[48];
            snprintf(t, sizeof(t), "%s/%d", cbuf, pfx);
            snprintf(cbuf, sizeof(cbuf), "%s", t);
        }
        return a2w(cbuf);
    }
    if (v->type == FWP_V6_ADDR_MASK && v->value.ptr)
    {
        W_V6_ADDR_AND_MASK* m = (W_V6_ADDR_AND_MASK*)v->value.ptr;
        struct in6_addr a6;
        char ipbuf[64];
        memcpy(&a6, m->addr, 16);
        if (!inet_ntop(AF_INET6, &a6, ipbuf, sizeof(ipbuf))) return NULL;
        if (m->prefixLength == 128) snprintf(cbuf, sizeof(cbuf), "%s", ipbuf);
        else snprintf(cbuf, sizeof(cbuf), "%s/%d", ipbuf, (int)m->prefixLength);
        return a2w(cbuf);
    }
    return NULL;
}

/* 端口条件 → "80" 或 "80-90" (宽串, 调用方 free) */
static wchar_t* extract_port(const W_VALUE0* v)
{
    char cbuf[32];
    if (v->type == FWP_UINT16)
    {
        snprintf(cbuf, sizeof(cbuf), "%u", v->value.uint16);
        return a2w(cbuf);
    }
    if (v->type == FWP_RANGE_TYPE && v->value.ptr)
    {
        W_RANGE0* r = (W_RANGE0*)v->value.ptr;
        unsigned lo = r->low.value.uint16;
        unsigned hi = r->high.value.uint16;
        snprintf(cbuf, sizeof(cbuf), "%u-%u", lo, hi);
        return a2w(cbuf);
    }
    return NULL;
}

static int cmd_update(int argc, wchar_t** argv, int argbase)
{
    unsigned long long fid, newId = 0;
    WENGINE h = NULL;
    void* p = NULL;
    W_FILTER0* f;
    W_FILTER0 fnew;
    long hr;
    int ret = 1;
    int i;

    /* 用户覆盖参数 (-2/-1 = 未指定) */
    wchar_t *name = NULL, *desc = NULL, *layerStr = NULL, *sublayerStr = NULL;
    int action_block = -1;
    int protocol = -2;
    int weight_set = -1, weight = 0;      /* -1=未指定 0=auto 1=指定 */
    int boottime = -1, volatileFlag = -1;
    wchar_t *lportStr = NULL, *rportStr = NULL;
    wchar_t *lips[8] = { NULL }; int lipCount = 0;
    wchar_t *rips[8] = { NULL }; int ripCount = 0;
    int has_lip = 0, has_rip = 0, has_lport = 0, has_rport = 0, has_app = 0;
    wchar_t* app = NULL;
    void* userAppBlob = NULL;

    /* 从旧规则提取的基值 */
    wchar_t *b_name = NULL, *b_desc = NULL;
    wchar_t *b_lip = NULL, *b_rip = NULL, *b_lport = NULL, *b_rport = NULL;
    int b_action_block = 0, b_proto = -1;
    int b_weight_set = 0, b_weight = 0, b_boottime = 0, b_volatile = 0;
    int b_has_app = 0;
    GUID b_layer, b_sublayer;
    void* b_appblob = NULL;               /* 深拷贝的 W_BYTE_BLOB (keep 管理) */

    /* 合成结果 */
    int F_has_lip = 0, F_has_rip = 0, F_has_lport = 0, F_has_rport = 0, F_has_app = 0;
    int F_proto;
    wchar_t *F_lips[8] = { NULL }; int F_lip_n = 0;
    wchar_t *F_rips[8] = { NULL }; int F_rip_n = 0;
    PortRange F_lport, F_rport;
    void* F_appblob = NULL;
    GUID final_layer, final_sublayer;

    KeepList keep;
    W_FILTER_CONDITION0 conds[8];
    int nc = 0;

    if (argbase >= argc)
    { fprintf(stderr, "用法: wfpctl_c update <规则ID> [参数]。未指定的参数保持原值; any 清除条件。\n"); return 1; }
    fid = _wcstoui64(argv[argbase], NULL, 10);
    if (fid == 0)
    { char* u = w2u(argv[argbase]); fprintf(stderr, "update: 无效的规则 ID: %s\n", u ? u : "?"); free(u); return 1; }

    keep.n = 0;
    memset(&b_layer, 0, sizeof(b_layer));
    memset(&b_sublayer, 0, sizeof(b_sublayer));

    /* 解析覆盖参数 */
    for (i = argbase + 1; i < argc; i++)
    {
        wchar_t* a = argv[i];
        if (wcscmp(a, L"--name") == 0 && i + 1 < argc) { free(name); name = wdup(argv[++i]); }
        else if (wcscmp(a, L"--desc") == 0 && i + 1 < argc) { free(desc); desc = wdup(argv[++i]); }
        else if (wcscmp(a, L"--action") == 0 && i + 1 < argc)
        {
            wchar_t* act = argv[++i];
            if (wcscmp(act, L"block") == 0) action_block = 1;
            else if (wcscmp(act, L"permit") == 0 || wcscmp(act, L"allow") == 0) action_block = 0;
            else { fprintf(stderr, "update: --action 仅支持 block 或 permit。\n"); goto done; }
        }
        else if (wcscmp(a, L"--protocol") == 0 && i + 1 < argc)
        {
            protocol = parse_protocol(argv[++i]);
            if (protocol == -2) { fprintf(stderr, "update: 无效的协议。\n"); goto done; }
        }
        else if (wcscmp(a, L"--lip") == 0 && i + 1 < argc)
        {
            wchar_t* v = argv[++i];
            has_lip = 1;
            if (wcscmp(v, L"any") == 0) lipCount = 0;
            else
            {
                if (lipCount >= 8) { fprintf(stderr, "update: --lip 参数过多 (最多 8 个)。\n"); goto done; }
                lips[lipCount++] = wdup(v);
            }
        }
        else if (wcscmp(a, L"--rip") == 0 && i + 1 < argc)
        {
            wchar_t* v = argv[++i];
            has_rip = 1;
            if (wcscmp(v, L"any") == 0) ripCount = 0;
            else
            {
                if (ripCount >= 8) { fprintf(stderr, "update: --rip 参数过多 (最多 8 个)。\n"); goto done; }
                rips[ripCount++] = wdup(v);
            }
        }
        else if (wcscmp(a, L"--lport") == 0 && i + 1 < argc)
        {
            wchar_t* v = argv[++i];
            has_lport = 1;
            if (wcscmp(v, L"any") == 0) { free(lportStr); lportStr = NULL; }
            else { free(lportStr); lportStr = wdup(v); }
        }
        else if (wcscmp(a, L"--rport") == 0 && i + 1 < argc)
        {
            wchar_t* v = argv[++i];
            has_rport = 1;
            if (wcscmp(v, L"any") == 0) { free(rportStr); rportStr = NULL; }
            else { free(rportStr); rportStr = wdup(v); }
        }
        else if (wcscmp(a, L"--app") == 0 && i + 1 < argc)
        {
            wchar_t* v = argv[++i];
            has_app = 1;
            if (wcscmp(v, L"any") == 0) { free(app); app = NULL; }
            else { free(app); app = wdup(v); }
        }
        else if (wcscmp(a, L"--weight") == 0 && i + 1 < argc)
        {
            wchar_t* v = argv[++i];
            if (wcscmp(v, L"auto") == 0) weight_set = 0;
            else
            {
                wchar_t* end;
                long w = wcstol(v, &end, 10);
                if (end == v || w < 0 || w > 15)
                { fprintf(stderr, "update: --weight 须为 0-15 或 auto。\n"); goto done; }
                weight_set = 1;
                weight = (int)w;
            }
        }
        else if (wcscmp(a, L"--boottime") == 0) boottime = 1;
        else if (wcscmp(a, L"--volatile") == 0) volatileFlag = 1;
        else if (wcscmp(a, L"--persistent") == 0) volatileFlag = 0;
        else if (wcscmp(a, L"--layer") == 0 && i + 1 < argc) { free(layerStr); layerStr = wdup(argv[++i]); }
        else if (wcscmp(a, L"--sublayer") == 0 && i + 1 < argc) { free(sublayerStr); sublayerStr = wdup(argv[++i]); }
        else { char* u = w2u(a); fprintf(stderr, "update: 无法识别的参数 %s\n", u ? u : "?"); free(u); goto done; }
    }

    if (boottime == 1 && volatileFlag == 1)
    { fprintf(stderr, "update: --boottime 与 --volatile 互斥。\n"); goto done; }

    if (!engine_open(&h)) goto done;
    hr = pFwpmFilterGetById0(h, fid, &p);
    if (hr != 0)
    {
        if ((unsigned int)hr == 0x80320003u)
            fprintf(stderr, "update: 未找到 ID 为 %llu 的规则。\n", fid);
        else
            g_err("获取规则 (FwpmFilterGetById0)", hr);
        goto close_engine;
    }
    f = (W_FILTER0*)p;
    if (f->action.type != FWP_ACTION_BLOCK && f->action.type != FWP_ACTION_PERMIT)
    { fprintf(stderr, "update: 仅支持修改 BLOCK/PERMIT 动作的规则。\n"); goto free_engine; }

    /* ---- 提取基值 (所有 BFE 内存读取在 FwpmFreeMemory0 前完成) ---- */
    b_name = wdup(f->displayData.name ? f->displayData.name : L"wfpctl rule");
    b_desc = wdup(f->displayData.description ? f->displayData.description : L"");
    b_action_block = (f->action.type == FWP_ACTION_BLOCK);
    b_layer = f->layerKey;
    b_sublayer = f->subLayerKey;
    b_boottime = (f->flags & WF_FLAG_BOOTTIME) ? 1 : 0;
    b_volatile = (!b_boottime && !(f->flags & WF_FLAG_PERSISTENT)) ? 1 : 0;
    b_weight_set = (f->weight.type == FWP_UINT8);
    if (b_weight_set) b_weight = f->weight.value.uint8;
    {
        unsigned int ci;
        int bad = 0;
        for (ci = 0; ci < f->numFilterConditions && !bad; ci++)
        {
            W_FILTER_CONDITION0* c = &f->filterCondition[ci];
            W_VALUE0* v = &c->conditionValue;
            if (guid_eq(&c->fieldKey, &COND_IP_PROTOCOL))
            {
                if (v->type == FWP_UINT8) b_proto = (int)v->value.uint8;
            }
            else if (guid_eq(&c->fieldKey, &COND_IP_LOCAL_ADDR))
            { b_lip = extract_addr(v); if (!b_lip) bad = 1; }
            else if (guid_eq(&c->fieldKey, &COND_IP_REMOTE_ADDR))
            { b_rip = extract_addr(v); if (!b_rip) bad = 1; }
            else if (guid_eq(&c->fieldKey, &COND_IP_LOCAL_PORT))
            { b_lport = extract_port(v); if (!b_lport) bad = 1; }
            else if (guid_eq(&c->fieldKey, &COND_IP_REMOTE_PORT))
            { b_rport = extract_port(v); if (!b_rport) bad = 1; }
            else if (guid_eq(&c->fieldKey, &COND_ALE_APP_ID))
            {
                if (v->type == FWP_BYTE_BLOB && v->value.ptr)
                {
                    W_BYTE_BLOB* src = (W_BYTE_BLOB*)v->value.ptr;
                    W_BYTE_BLOB* nb;
                    unsigned char* data;
                    if (src->size && src->data)
                    {
                        nb = (W_BYTE_BLOB*)malloc(sizeof(W_BYTE_BLOB));
                        data = (unsigned char*)malloc(src->size);
                        if (nb && data)
                        {
                            nb->size = src->size;
                            nb->data = data;
                            memcpy(data, src->data, src->size);
                            keep_add(&keep, nb);
                            keep_add(&keep, data);
                            b_appblob = nb;
                            b_has_app = 1;
                        }
                        else { free(nb); free(data); }
                    }
                }
            }
            else
            {
                const wchar_t* fn = field_name(&c->fieldKey);
                char g[48];
                if (fn)
                {
                    char* u = w2u(fn);
                    _snprintf(g, sizeof(g), "%s", u ? u : "?");
                    if (u) free(u);
                }
                else fmt_guid(&c->fieldKey, g, 48);
                fprintf(stderr, "update: 该规则含本工具无法编辑的条件 (%s), 请删除后重新添加。\n", g);
                bad = 1;
            }
        }
        if (bad) goto free_engine;
    }
    pFwpmFreeMemory0(&p);
    p = NULL;

    /* ---- 合成最终值 (用户覆盖 > 旧值) ---- */
    if (!name) { name = b_name; b_name = NULL; }
    if (!desc) { desc = b_desc; b_desc = NULL; }
    if (action_block < 0) action_block = b_action_block;
    if (protocol == -2) F_proto = b_proto; else F_proto = protocol;
    if (boottime < 0) boottime = b_boottime;
    if (volatileFlag < 0) volatileFlag = b_volatile;
    if (weight_set < 0) { weight_set = b_weight_set ? 1 : 0; weight = b_weight; }

    if (layerStr)
    {
        if (!resolve_layer(layerStr, &final_layer))
        { char* u = w2u(layerStr); fprintf(stderr, "update: 无法识别的层 \"%s\"。\n", u ? u : "?"); free(u); goto free_engine; }
    }
    else final_layer = b_layer;
    if (sublayerStr)
    {
        if (wcscmp(sublayerStr, L"default") == 0) final_sublayer = WFPCTL_SUBLAYER;
        else if (!parse_guid(sublayerStr, &final_sublayer))
        { char* u = w2u(sublayerStr); fprintf(stderr, "update: 无效的子层 GUID: %s\n", u ? u : "?"); free(u); goto free_engine; }
    }
    else final_sublayer = b_sublayer;

    if (has_app)
    {
        if (app)
        {
            unsigned int rc = pFwpmGetAppIdFromFileName0(app, &userAppBlob);
            if (rc != 0)
            { char* u = w2u(app); fprintf(stderr, "update: 获取应用程序 ID 失败 (0x%08X)。请确认文件路径存在。\n", rc); free(u); goto free_engine; }
            F_appblob = userAppBlob;
            F_has_app = 1;
        }
        /* --app any → 清除应用条件 */
    }
    else if (b_has_app) { F_appblob = b_appblob; F_has_app = 1; }

    if (has_lip)
    {
        int _j;
        F_lip_n = lipCount;
        F_has_lip = (lipCount > 0);
        for (_j = 0; _j < lipCount; _j++) F_lips[_j] = lips[_j];
    }
    else { F_has_lip = (b_lip != NULL); F_lip_n = b_lip ? 1 : 0; if (b_lip) F_lips[0] = b_lip; }
    if (has_rip)
    {
        int _j;
        F_rip_n = ripCount;
        F_has_rip = (ripCount > 0);
        for (_j = 0; _j < ripCount; _j++) F_rips[_j] = rips[_j];
    }
    else { F_has_rip = (b_rip != NULL); F_rip_n = b_rip ? 1 : 0; if (b_rip) F_rips[0] = b_rip; }

    if (has_lport)
    {
        if (lportStr)
        {
            if (parse_port_list(lportStr, &F_lport, 1) != 1)
            { fprintf(stderr, "update: 每次只修改一条规则, --lport 仅接受单端口或单范围 (如 80 / 80-90)。\n"); goto free_engine; }
            F_has_lport = 1;
        }
    }
    else if (b_lport)
    {
        if (parse_port_list(b_lport, &F_lport, 1) != 1)
        { fprintf(stderr, "update: 原规则的端口条件无法解析。\n"); goto free_engine; }
        F_has_lport = 1;
    }
    if (has_rport)
    {
        if (rportStr)
        {
            if (parse_port_list(rportStr, &F_rport, 1) != 1)
            { fprintf(stderr, "update: 每次只修改一条规则, --rport 仅接受单端口或单范围 (如 80 / 80-90)。\n"); goto free_engine; }
            F_has_rport = 1;
        }
    }
    else if (b_rport)
    {
        if (parse_port_list(b_rport, &F_rport, 1) != 1)
        { fprintf(stderr, "update: 原规则的端口条件无法解析。\n"); goto free_engine; }
        F_has_rport = 1;
    }

    /* ---- 构造条件数组 ---- */
    if (F_proto >= 0)
    {
        memset(&conds[nc], 0, sizeof(conds[nc]));
        conds[nc].fieldKey = COND_IP_PROTOCOL;
        conds[nc].matchType = FWP_MATCH_EQUAL;
        conds[nc].conditionValue.type = FWP_UINT8;
        conds[nc].conditionValue.value.uint8 = (unsigned char)F_proto;
        nc++;
    }
    if (F_has_rip || F_has_lip)
    {
        int _j;
for (_j = 0; _j < F_rip_n; _j++)
        {
            if (!add_ip_cond(&keep, &conds[nc], &COND_IP_REMOTE_ADDR, F_rips[_j]))
            { char* u = w2u(F_rips[_j]); fprintf(stderr, "update: 无法解析 IP 地址: %s\n", u ? u : "?"); free(u); goto free_engine; }
            nc++;
        }
        for (_j = 0; _j < F_lip_n; _j++)
        {
            if (!add_ip_cond(&keep, &conds[nc], &COND_IP_LOCAL_ADDR, F_lips[_j]))
            { char* u = w2u(F_lips[_j]); fprintf(stderr, "update: 无法解析 IP 地址: %s\n", u ? u : "?"); free(u); goto free_engine; }
            nc++;
        }
    }
    if (F_has_lport)
    {
        if (!add_port_cond(&keep, &conds[nc], &COND_IP_LOCAL_PORT, F_lport)) goto free_engine;
        nc++;
    }
    if (F_has_rport)
    {
        if (!add_port_cond(&keep, &conds[nc], &COND_IP_REMOTE_PORT, F_rport)) goto free_engine;
        nc++;
    }
    if (F_has_app)
    {
        memset(&conds[nc], 0, sizeof(conds[nc]));
        conds[nc].fieldKey = COND_ALE_APP_ID;
        conds[nc].matchType = FWP_MATCH_EQUAL;
        conds[nc].conditionValue.type = FWP_BYTE_BLOB;
        conds[nc].conditionValue.value.ptr = F_appblob;
        nc++;
    }

    /* ---- 事务: 删旧 + 建新 ---- */
    memset(&fnew, 0, sizeof(fnew));
    fnew.layerKey = final_layer;
    fnew.subLayerKey = final_sublayer;
    if (boottime) fnew.flags = WF_FLAG_BOOTTIME;
    else if (!volatileFlag) fnew.flags = WF_FLAG_PERSISTENT;
    if (weight_set) { fnew.weight.type = FWP_UINT8; fnew.weight.value.uint8 = (unsigned char)weight; }
    fnew.action.type = action_block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    fnew.displayData.name = name;
    fnew.displayData.description = desc;
    fnew.numFilterConditions = (unsigned int)nc;
    fnew.filterCondition = conds;

    hr = pFwpmTransactionBegin0(h, 0);
    if (hr != 0) { g_err("开始事务", hr); goto free_engine; }
    hr = pFwpmFilterDeleteById0(h, fid);
    if (hr != 0)
    {
        fprintf(stderr, "update: 删除旧规则 %llu 失败: 0x%08X\n", fid, (unsigned int)hr);
        pFwpmTransactionAbort0(h);
        goto free_engine;
    }
    hr = pFwpmFilterAdd0(h, &fnew, NULL, &newId);
    if (hr != 0)
    {
        fprintf(stderr, "错误: 重建规则失败 (FwpmFilterAdd0): 0x%08X\n", (unsigned int)hr);
        pFwpmTransactionAbort0(h);
        goto free_engine;
    }
    hr = pFwpmTransactionCommit0(h);
    if (hr != 0)
    { g_err("提交事务", hr); pFwpmTransactionAbort0(h); goto free_engine; }

    {
        char* nm = w2u(name);
        printf("已修改规则: ID %llu → %llu  名称 = %s\n", fid, newId, nm ? nm : "?");
        free(nm);
    }
    ret = 0;

free_engine:
    if (userAppBlob) pFwpmFreeMemory0(&userAppBlob);
    keep_free_all(&keep);
    free(b_name); free(b_desc); free(b_lip); free(b_rip); free(b_lport); free(b_rport);
close_engine:
    engine_close(h);
done:
    free(name); free(desc); free(layerStr); free(sublayerStr);
    free(lportStr); free(rportStr); free(app);
    { int _j; for (_j = 0; _j < lipCount; _j++) free(lips[_j]); for (_j = 0; _j < ripCount; _j++) free(rips[_j]); }
    return ret;
}

/* ==========================================================================
 * 命令: sublayer-add / sublayer-del
 * ======================================================================== */
static int cmd_sublayer_add(int argc, wchar_t** argv, int argbase)
{
    GUID key;
    unsigned short weight = 0x100;
    WENGINE h;
    long hr;
    if (argc - argbase != 2 && argc - argbase != 3)
    { fprintf(stderr, "用法: wfpctl_c sublayer-add <GUID|default> <名称> [权重0-65535]\n"); return 1; }
    if (wcscmp(argv[argbase], L"default") == 0) key = WFPCTL_SUBLAYER;
    else if (!parse_guid(argv[argbase], &key))
    { fprintf(stderr, "sublayer-add: 无效的 GUID。\n"); return 1; }
    if (argc - argbase == 3)
    {
        wchar_t* end;
        long w = wcstol(argv[argbase + 2], &end, 10);
        if (end == argv[argbase + 2] || w < 0 || w > 65535)
        { fprintf(stderr, "sublayer-add: 权重须为 0-65535。\n"); return 1; }
        weight = (unsigned short)w;
    }
    if (!engine_open(&h)) return 1;
    hr = ensure_sublayer(h, &key, argv[argbase + 1], weight);
    if (hr != 0) { g_err("添加子层", hr); engine_close(h); return 1; }
    { char g[48]; char* nm = w2u(argv[argbase + 1]); fmt_guid(&key, g, 48);
      printf("子层已就绪: {%s} 名称 = %s\n", g, nm ? nm : "?"); if (nm) free(nm); }
    engine_close(h);
    return 0;
}

static int cmd_sublayer_del(int argc, wchar_t** argv, int argbase)
{
    GUID key;
    WENGINE h;
    long hr;
    if (argc - argbase != 1)
    { fprintf(stderr, "用法: wfpctl_c sublayer-del <GUID|default>\n"); return 1; }
    if (wcscmp(argv[argbase], L"default") == 0) key = WFPCTL_SUBLAYER;
    else if (!parse_guid(argv[argbase], &key))
    { fprintf(stderr, "sublayer-del: 无效的 GUID。\n"); return 1; }
    if (!engine_open(&h)) return 1;
    hr = pFwpmSubLayerDeleteByKey0(h, &key);
    if (hr != 0)
    {
        unsigned int u = (unsigned int)hr;
        if (u == 0x80320007u) fprintf(stderr, "sublayer-del: 未找到该子层。\n");
        else if (u == 0x8032000Au) fprintf(stderr, "sublayer-del: 该子层下仍有过滤规则, 请先删除其规则。\n");
        else fprintf(stderr, "错误: 删除子层失败: 0x%08X\n", u);
        engine_close(h);
        return 1;
    }
    { char g[48]; fmt_guid(&key, g, 48); printf("已删除子层: {%s}\n", g); }
    engine_close(h);
    return 0;
}

/* ==========================================================================
 * 帮助
 * ======================================================================== */
static void usage(void)
{
    int k;
    printf("\nwfpctl_c —— Windows 过滤平台 (WFP) 过滤规则管理工具  v1.8 (C 版)\n\n");
    printf("用法: wfpctl_c <命令> [选项]\n\n");
    printf("命令:\n");
    printf("  add          添加过滤规则\n");
    printf("  del          删除过滤规则 (按 ID 或 --name 按名称)\n");
    printf("  update       修改规则: update <ID> [参数], 未指定的保持原值\n");
    printf("  list         列出过滤规则 (--all 看系统全部, 默认只看本工具建的)\n");
    printf("  show         查看规则详情\n");
    printf("  dump         导出规则为 add 命令: dump <ID> 或 dump --name <关键字>\n");
    printf("  layers       列出本机所有 WFP 过滤层\n");
    printf("  sublayers    列出所有子层\n");
    printf("  sublayer-add 添加子层\n");
    printf("  sublayer-del 删除子层\n");
    printf("  help         显示本帮助\n\n");
    printf("add 选项:\n");
    printf("  --name <名称>            规则显示名 (默认 \"wfpctl rule\")\n");
    printf("  --desc <描述>            规则描述\n");
    printf("  --action <block|permit>  匹配后动作, 默认 permit (放行); 阻断需显式 --action block\n");
    printf("  --layer <层>             过滤层, 别名或 GUID, 默认 connect-v4\n");
    for (k = 0; k < (int)(sizeof(g_layers) / sizeof(g_layers[0])); k++)
    { char* a = w2u(g_layers[k].alias); printf("    %-11s  %s\n", a ? a : "?", g_layers[k].desc); if (a) free(a); }
    printf("  --sublayer <GUID>        所属子层, 默认使用本工具内置子层 (与 exe/py 版共享)\n");
    printf("  --protocol <p>           协议: tcp|udp|icmp|icmpv6|数字(0-255)\n");
    printf("  --lport <端口>           本地端口: 80 / 80-90 / 80,443 (多值拆成多条规则)\n");
    printf("  --rport <端口>           远程端口, 同上\n");
    printf("  --lip <IP[/掩码]>        本地地址: 10.0.0.5 / 10.0.0.0/8 / IPv6\n");
    printf("  --rip <IP[/掩码]>        远程地址, 同上\n");
    printf("  --app <程序路径>         按应用过滤, 文件必须存在\n");
    printf("  --weight <0-15>          过滤器权重, 同子层内高的先评估 (缺省自动分配);\n");
    printf("                            例如白名单场景: PERMIT 例外用 15, 整体 BLOCK 用 0\n");
    printf("  --boottime               创建为启动时间规则 (BFE 未启动时即生效)\n");
    printf("  --volatile               规则不持久化, 重启 BFE 后消失 (默认持久)\n\n");
    printf("list 选项:\n");
    printf("  --all                    列出系统全部过滤规则\n");
    printf("  --name <关键字>          按名称/描述关键字筛选 (不区分大小写, 可与 --all 组合)\n");
    printf("  --action <block|permit>  按动作筛选\n");
    printf("  --layer <层>             按层筛选\n");
    printf("  --sublayer <GUID|名称|default> 按子层筛选 (名称支持模糊匹配, 可命中多个子层)\n\n");
    printf("update 选项 (在 add 参数基础上, 未指定的参数保持原值):\n");
    printf("  update <ID> --rport 443        修改远程端口 (单值或单范围)\n");
    printf("  update <ID> --action block     改为阻断\n");
    printf("  update <ID> --rip any          清除远程地址条件 (any 即清除)\n");
    printf("  update <ID> --weight auto      恢复自动权重\n");
    printf("  修改为事务内“删旧+建新”, 规则 ID 会变化, 失败自动回滚。\n\n");
    printf("示例:\n");
    printf("  wfpctl_c add --name \"禁出站80端口\" --action block --protocol tcp --rport 80\n");
    printf("  wfpctl_c add --name \"禁访问某网段\" --action block --rip 203.0.113.0/24\n");
    printf("  wfpctl_c add --name \"白名单\" --rip 1.2.3.4 --weight 15\n");
    printf("  wfpctl_c list --name 80端口\n");
    printf("  wfpctl_c list --all --name mssec\n");
    printf("  wfpctl_c show 12345\n");
    printf("  wfpctl_c dump 12345\n");
    printf("  wfpctl_c dump --name 80端口\n");
    printf("  wfpctl_c update 12345 --rport 443\n");
    printf("  wfpctl_c del 12345\n\n");
    printf("说明:\n");
    printf("  * 增删规则需要管理员权限 (依赖系统 BFE 服务)。\n");
    printf("  * 规则默认持久化, 重启系统后仍生效; 与 wfpctl.exe / wfpctl.py 共用同一子层。\n");
    printf("  * 端口范围按网络字节序数值区间匹配, 跨高字节块的范围 (如 1000-2000)\n");
    printf("    会被 BFE 拒绝, 此时请改用逗号列举端口。\n\n");
}

/* ==========================================================================
 * 自检 + 入口
 * ======================================================================== */
static int self_check(void)
{
    if (sizeof(W_VALUE0) != 16) { fprintf(stderr, "自检失败: FWP_VALUE0 = %zu (应为 16)\n", sizeof(W_VALUE0)); return 0; }
    if (sizeof(W_RANGE0) != 32) { fprintf(stderr, "自检失败: FWP_RANGE0 = %zu (应为 32)\n", sizeof(W_RANGE0)); return 0; }
    if (sizeof(W_FILTER_CONDITION0) != 40) { fprintf(stderr, "自检失败: 条件 = %zu (应为 40)\n", sizeof(W_FILTER_CONDITION0)); return 0; }
    if (sizeof(W_FILTER0) != 200) { fprintf(stderr, "自检失败: FWPM_FILTER0 = %zu (应为 200, 非 x64?)\n", sizeof(W_FILTER0)); return 0; }
    if (sizeof(void*) != 8) { fprintf(stderr, "自检失败: 需要 64 位编译目标。\n"); return 0; }
    return 1;
}

int main(void)
{
    int argc = 0, i;
    wchar_t** argv;
    const wchar_t* cmd;

    SetConsoleOutputCP(65001);
    if (!wfp_bind()) return 1;
    if (!self_check()) return 1;

    argv = pCommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 2) { usage(); return 1; }
    cmd = argv[1];

    if (wcscmp(cmd, L"help") == 0 || wcscmp(cmd, L"--help") == 0 ||
        wcscmp(cmd, L"-h") == 0 || wcscmp(cmd, L"/?") == 0)
    { usage(); return 0; }
    if (wcscmp(cmd, L"add") == 0) return cmd_add(argc, argv, 2);
    if (wcscmp(cmd, L"del") == 0 || wcscmp(cmd, L"delete") == 0) return cmd_del(argc, argv, 2);
    if (wcscmp(cmd, L"update") == 0 || wcscmp(cmd, L"upd") == 0) return cmd_update(argc, argv, 2);
    if (wcscmp(cmd, L"list") == 0 || wcscmp(cmd, L"ls") == 0) return cmd_list(argc, argv, 2);
    if (wcscmp(cmd, L"show") == 0)
    {
        if (argc != 3) { fprintf(stderr, "用法: wfpctl_c show <规则ID>\n"); return 1; }
        return cmd_show(_wcstoui64(argv[2], NULL, 10));
    }
    if (wcscmp(cmd, L"dump") == 0) return cmd_dump(argc, argv, 2);
    if (wcscmp(cmd, L"layers") == 0) return cmd_layers();
    if (wcscmp(cmd, L"sublayers") == 0) return cmd_sublayers();
    if (wcscmp(cmd, L"sublayer-add") == 0) return cmd_sublayer_add(argc, argv, 2);
    if (wcscmp(cmd, L"sublayer-del") == 0) return cmd_sublayer_del(argc, argv, 2);

    { char* u = w2u(cmd); fprintf(stderr, "未知命令: %s\n", u ? u : "?"); free(u); }
    usage();
    return 1;
}
