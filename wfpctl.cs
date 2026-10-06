// ============================================================================
//  wfpctl.cs —— Windows 过滤平台 (WFP) 过滤规则管理命令行工具
//
//  功能:
//    add          添加过滤规则 (协议/端口/IP/应用程序 条件, BLOCK 或 PERMIT)
//    del          删除过滤规则 (按 ID 或按名称)
//    list         列出过滤规则 (默认只列本工具创建的, --all 列系统全部)
//    show         查看规则详情 (含全部匹配条件)
//    layers       列出本机所有 WFP 过滤层
//    sublayers    列出所有子层
//    sublayer-add / sublayer-del   添加 / 删除子层
//
//  编译 (本机自带 .NET Framework 编译器, 无需安装任何环境):
//    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /t:exe
//      /platform:anycpu /optimize+ /codepage:65001 /out:wfpctl.exe wfpctl.cs
//
//  说明:
//    - 通过 P/Invoke 直接调用系统 fwpuclnt.dll (BFE 服务客户端), 数据本地处理。
//    - 增删操作需要管理员权限。
//    - 常量取自官方 SDK 头文件 fwpmu.h / fwptypes.h / fwpmtypes.h。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WfpCtl
{
    // ------------------------------------------------------------------
    // 原生结构体定义 (与 fwpmtypes.h / fwptypes.h 严格对应, x64 布局)
    // ------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_DISPLAY_DATA0
    {
        public IntPtr name;         // wchar_t*
        public IntPtr description;  // wchar_t*
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    // FWP_VALUE0 / FWP_CONDITION_VALUE0 共用的联合体:
    // 标量内联, 8 字节及以上类型(含指针)以指针表示
    [StructLayout(LayoutKind.Explicit)]
    internal struct FwpValueUnion
    {
        [FieldOffset(0)] public byte uint8;
        [FieldOffset(0)] public ushort uint16;
        [FieldOffset(0)] public uint uint32;
        [FieldOffset(0)] public float float32;
        [FieldOffset(0)] public IntPtr ptr;    // uint64*/int64*/double*/byteArray16*/blob/sid/v4mask/v6mask/range
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_VALUE0
    {
        public uint type;                  // FWP_DATA_TYPE
        public FwpValueUnion value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_RANGE0
    {
        public FWP_VALUE0 low;
        public FWP_VALUE0 high;
    }

    // MIDL: UINT32 type + union{GUID filterType; GUID calloutKey;}
    // x64 下 union 对齐 8, type(4) 后需 4 字节 padding, 再跟 16 字节 GUID → 总 24 字节
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    internal struct FWPM_ACTION0
    {
        [FieldOffset(0)]  public uint type;    // FWP_ACTION_TYPE
        [FieldOffset(8)]  public Guid calloutKey; // union{GUID filterType; GUID calloutKey;} 取 calloutKey 即可
    }

    // native 条件间距 = 48 字节 (实测); .NET 默认布局 40 字节, 差 8 字节
    // 原因: MIDL [switch_is] union 的 native 打包比 CLR 多 8 字节
    // 用 Explicit 布局强制对齐: fieldKey(0-15) matchType(16-19) pad(20-23)
    //   conditionValue.type(24-27) pad(28-31) conditionValue.value(32-39) pad(40-47)
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;             // FWP_MATCH_TYPE
        public FWP_VALUE0 conditionValue;
    }
    // 条件数组中每个元素的实际字节间距 (native 打包大小 = 48, 而非 CLR 的 40)
    // 必须用此值读写条件数组, 否则 BFE 读到的条件数据会错位
    internal static class WfpConst
    {
        public const int ConditionStride = 48;
    }

    // FWPM_FILTER0 中的联合体: UINT64 rawContext / GUID providerContextKey (16 字节, 对齐 8)
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FilterContextUnion
    {
        [FieldOffset(0)] public IntPtr rawContext;        // 8 字节
        [FieldOffset(0)] public Guid providerContextKey;  // 16 字节
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public FilterContextUnion context;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SUB_LAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_LAYER0
    {
        public Guid layerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint numFields;
        public IntPtr field;               // FWPM_FIELD0*
        public Guid defaultSubLayerKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;                  // 网络字节序
        public uint mask;                  // 网络字节序
    }

    internal static class Native
    {
        public const uint RPC_C_AUTHN_WINNT = 10;

        // FWP_ACTION_TYPE (fwptypes.h)
        public const uint FWP_ACTION_BLOCK  = 0x00000001 | 0x00001000; // TERMINATING
        public const uint FWP_ACTION_PERMIT = 0x00000002 | 0x00001000;
        public const uint FWP_ACTION_CALLOUT_TERMINATING = 0x00000003 | 0x00004000 | 0x00001000;
        public const uint FWP_ACTION_CALLOUT_INSPECTION  = 0x00000004 | 0x00004000 | 0x00002000;
        public const uint FWP_ACTION_CALLOUT_UNKNOWN    = 0x00000005 | 0x00004000;
        public const uint FWP_ACTION_CONTINUE           = 0x00000006 | 0x00002000;

        // FWPM_FILTER_FLAG (fwpmtypes.h)
        public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;
        public const uint FWPM_FILTER_FLAG_BOOTTIME   = 0x00000002;
        public const uint FWPM_FILTER_FLAG_DISABLED   = 0x00000020;
        public const uint FWPM_FILTER_FLAG_INDEXED    = 0x00000040;

        // FWPM_SUBLAYER_FLAG (fwpmtypes.h)
        public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;

        // FWP_MATCH_TYPE (fwptypes.h)
        public const uint FWP_MATCH_EQUAL              = 0;
        public const uint FWP_MATCH_GREATER            = 1;
        public const uint FWP_MATCH_LESS               = 2;
        public const uint FWP_MATCH_GREATER_OR_EQUAL   = 3;
        public const uint FWP_MATCH_LESS_OR_EQUAL      = 4;
        public const uint FWP_MATCH_RANGE              = 5;
        public const uint FWP_MATCH_FLAGS_ALL_SET      = 6;
        public const uint FWP_MATCH_FLAGS_ANY_SET      = 7;
        public const uint FWP_MATCH_FLAGS_NONE_SET     = 8;
        public const uint FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9;
        public const uint FWP_MATCH_NOT_EQUAL          = 10;
        public const uint FWP_MATCH_PREFIX             = 11;

        // FWP_DATA_TYPE (fwptypes.h)
        public const uint FWP_EMPTY                    = 0;
        public const uint FWP_UINT8                    = 1;
        public const uint FWP_UINT16                   = 2;
        public const uint FWP_UINT32                   = 3;
        public const uint FWP_UINT64                   = 4;
        public const uint FWP_INT8                     = 5;
        public const uint FWP_INT16                    = 6;
        public const uint FWP_INT32                    = 7;
        public const uint FWP_INT64                    = 8;
        public const uint FWP_FLOAT                    = 9;
        public const uint FWP_DOUBLE                   = 10;
        public const uint FWP_BYTE_ARRAY16_TYPE        = 11;
        public const uint FWP_BYTE_BLOB_TYPE           = 12;
        public const uint FWP_SID                      = 13;
        public const uint FWP_SECURITY_DESCRIPTOR_TYPE = 14;
        public const uint FWP_TOKEN_INFORMATION_TYPE   = 15;
        public const uint FWP_TOKEN_ACCESS_INFORMATION_TYPE = 16;
        public const uint FWP_UNICODE_STRING_TYPE      = 17;
        public const uint FWP_BYTE_ARRAY6_TYPE        = 18;
        public const uint FWP_V4_ADDR_MASK             = 0x100;
        public const uint FWP_V6_ADDR_MASK             = 0x101;
        public const uint FWP_RANGE_TYPE               = 0x102;

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern int FwpmEngineOpen0(string serverName, uint authnService,
            IntPtr authnIdentity, IntPtr session, out IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmEngineClose0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmTransactionBegin0(IntPtr h, uint flags);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmTransactionCommit0(IntPtr h);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmTransactionAbort0(IntPtr h);

        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFilterAdd0(IntPtr h, ref FWPM_FILTER0 filter,
            IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFilterDeleteById0(IntPtr h, ulong id);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFilterGetById0(IntPtr h, ulong id, out IntPtr filter);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFilterCreateEnumHandle0(IntPtr h, IntPtr tmpl, out IntPtr enumHandle);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFilterEnum0(IntPtr h, IntPtr enumHandle,
            uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFilterDestroyEnumHandle0(IntPtr h, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmSubLayerAdd0(IntPtr h, ref FWPM_SUB_LAYER0 sublayer, IntPtr sd);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmSubLayerDeleteByKey0(IntPtr h, ref Guid key);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmSubLayerCreateEnumHandle0(IntPtr h, IntPtr tmpl, out IntPtr enumHandle);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmSubLayerEnum0(IntPtr h, IntPtr enumHandle,
            uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmSubLayerDestroyEnumHandle0(IntPtr h, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmLayerCreateEnumHandle0(IntPtr h, IntPtr tmpl, out IntPtr enumHandle);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmLayerEnum0(IntPtr h, IntPtr enumHandle,
            uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmLayerDestroyEnumHandle0(IntPtr h, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmFreeMemory0(ref IntPtr p);

        // 该函数返回 Win32 错误码 (0 = 成功)
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern int FwpmGetAppIdFromFileName0(string fileName, out IntPtr appIdBlob);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr sd, int revision, int secInfo, out IntPtr str, out uint len);
        [DllImport("fwpuclnt.dll")]
        public static extern int FwpmProviderGetByKey0(IntPtr engine, ref Guid key, out IntPtr provider);
        [DllImport("kernel32.dll")]
        public static extern void LocalFree(IntPtr h);
    }

    // ------------------------------------------------------------------
    // WFP 常量 GUID —— 全部提取自官方 SDK 头文件 fwpmu.h
    // ------------------------------------------------------------------
    internal static class WfpGuids
    {
        // 过滤层
        public static readonly Guid LayerAleAuthConnectV4     = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid LayerAleAuthConnectV6     = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid LayerAleAuthRecvAcceptV4  = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        public static readonly Guid LayerAleAuthRecvAcceptV6  = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
        public static readonly Guid LayerOutboundTransportV4  = new Guid("09e61aea-d214-46e2-9b21-b26b0b2f28c8");
        public static readonly Guid LayerOutboundTransportV6  = new Guid("e1735bde-013f-4655-b351-a49e15762df0");
        public static readonly Guid LayerInboundTransportV4   = new Guid("5926dfc8-e3cf-4426-a283-dc393f5d0f9d");
        public static readonly Guid LayerInboundTransportV6   = new Guid("634a869f-fc23-4b90-b0c1-bf620a36ae6f");

        // 过滤条件字段
        public static readonly Guid CondIpProtocol     = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        public static readonly Guid CondIpLocalAddr   = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
        public static readonly Guid CondIpRemoteAddr  = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        public static readonly Guid CondIpLocalPort   = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
        public static readonly Guid CondIpRemotePort  = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        public static readonly Guid CondAleAppId      = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        public static readonly Guid CondAleUserId     = new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");
        public static readonly Guid CondIpsecQmSaId   = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");

        // 本工具默认子层 (固定 GUID, 便于识别本工具创建的规则; 持久化)
        public static readonly Guid WfpCtlSublayer    = new Guid("b7c4f2a1-3e5d-4a90-8b1c-6f2e7d8a9b3c");

        public static bool IsKnownCondition(Guid g)
        {
            return g == CondIpProtocol || g == CondIpLocalAddr || g == CondIpRemoteAddr
                || g == CondIpLocalPort || g == CondIpRemotePort || g == CondAleAppId;
        }
    }

    // ------------------------------------------------------------------
    // 层别名 <-> GUID
    // ------------------------------------------------------------------
    internal static class LayerAlias
    {
        private class AliasInfo { public string alias; public Guid guid; public string desc; }
        private static readonly AliasInfo[] s_layers = new AliasInfo[]
        {
            new AliasInfo { alias = "connect-v4", guid = WfpGuids.LayerAleAuthConnectV4,    desc = "出站连接授权 (ALE)" },
            new AliasInfo { alias = "connect-v6", guid = WfpGuids.LayerAleAuthConnectV6,    desc = "出站连接授权 (ALE, IPv6)" },
            new AliasInfo { alias = "accept-v4",  guid = WfpGuids.LayerAleAuthRecvAcceptV4, desc = "入站连接授权 (ALE)" },
            new AliasInfo { alias = "accept-v6",  guid = WfpGuids.LayerAleAuthRecvAcceptV6, desc = "入站连接授权 (ALE, IPv6)" },
            new AliasInfo { alias = "out-v4",     guid = WfpGuids.LayerOutboundTransportV4, desc = "出站传输层" },
            new AliasInfo { alias = "out-v6",     guid = WfpGuids.LayerOutboundTransportV6, desc = "出站传输层 (IPv6)" },
            new AliasInfo { alias = "in-v4",      guid = WfpGuids.LayerInboundTransportV4,  desc = "入站传输层" },
            new AliasInfo { alias = "in-v6",      guid = WfpGuids.LayerInboundTransportV6,  desc = "入站传输层 (IPv6)" },
        };

        public static bool IsAlias(string s)
        {
            foreach (AliasInfo a in s_layers) if (a.alias == s) return true;
            return false;
        }

        // 解析别名或 "{GUID}" / "GUID"
        public static Guid Resolve(string s)
        {
            foreach (AliasInfo a in s_layers)
                if (string.Compare(a.alias, s, StringComparison.OrdinalIgnoreCase) == 0) return a.guid;

            Guid g;
            if (GuidTryParseLoose(s, out g)) return g;
            return Guid.Empty;
        }

        public static string AliasOf(Guid g)
        {
            foreach (AliasInfo a in s_layers) if (a.guid == g) return a.alias;
            return null;
        }

        public static string DescOf(Guid g)
        {
            foreach (AliasInfo a in s_layers) if (a.guid == g) return a.desc;
            return null;
        }

        public static string ListForHelp()
        {
            StringBuilder sb = new StringBuilder();
            foreach (AliasInfo a in s_layers)
                sb.Append("  ").Append(a.alias.PadRight(11)).Append("  ").Append(a.desc)
                  .AppendLine();
            return sb.ToString();
        }

        private static bool GuidTryParseLoose(string s, out Guid g)
        {
            g = Guid.Empty;
            if (string.IsNullOrEmpty(s)) return false;
            try
            {
                string t = s.Trim();
                if (t.StartsWith("{")) t = t.Trim('{', '}');
                if (t.EndsWith("}")) t = t.TrimEnd('}');
                g = new Guid(t);
                return true;
            }
            catch { return false; }
        }
    }

    // ------------------------------------------------------------------
    // WFP 引擎封装
    // ------------------------------------------------------------------
    internal sealed class WfpEngine : IDisposable
    {
        private IntPtr m_handle = IntPtr.Zero;

        public IntPtr Handle { get { return m_handle; } }

        public void Open()
        {
            if (m_handle != IntPtr.Zero) return;
            IntPtr h;
            int hr = Native.FwpmEngineOpen0(null, Native.RPC_C_AUTHN_WINNT,
                IntPtr.Zero, IntPtr.Zero, out h);
            if (hr != 0)
            {
                if ((uint)hr == 0x80070005)
                    throw new WfpException(hr,
                        "打开 BFE 引擎被拒绝。请以管理员身份运行本工具。");
                throw new WfpException(hr, "打开 WFP 引擎失败 (FwpmEngineOpen0)。");
            }
            m_handle = h;
        }

        public void Dispose()
        {
            if (m_handle != IntPtr.Zero)
            {
                Native.FwpmEngineClose0(m_handle);
                m_handle = IntPtr.Zero;
            }
        }

        // ---------- 通用枚举 ----------
        // Func<> 不支持 out 参数, 使用专用委托表示 WFP 枚举函数
        private delegate int WfpEnumDeleg(IntPtr engine, IntPtr enumHandle, uint max,
            out IntPtr entries, out uint count);

        // 通用枚举: 每批取回结构体指针数组, 在 FwpmFreeMemory0 之前完成深拷贝
        private static List<T> EnumObjects<T>(IntPtr engine,
            Func<IntPtr, IntPtr> create,
            Action<IntPtr, IntPtr> destroy,
            WfpEnumDeleg enumerate,
            Func<IntPtr, T> copy)
        {
            List<T> result = new List<T>();
            IntPtr enumHandle = create(engine);
            try
            {
                for (; ; )
                {
                    IntPtr entries; uint count;
                    int hr = enumerate(engine, enumHandle, 512, out entries, out count);
                    if (hr != 0) throw new WfpException(hr, "枚举 WFP 对象失败。");
                    if (count == 0) break;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        result.Add(copy(p));   // BFE 内存此刻有效, 立即深拷贝
                    }
                    Native.FwpmFreeMemory0(ref entries);
                    if (count < 512) break;
                }
            }
            finally
            {
                destroy(engine, enumHandle);
            }
            return result;
        }

        // ---- 深拷贝函数 (必须在原生内存释放前调用) ----

        private static string Str(IntPtr p)
        {
            return (p == IntPtr.Zero) ? null : Marshal.PtrToStringUni(p);
        }

        internal static V CopyValue(FWP_VALUE0 v)
        {
            switch (v.type)
            {
                case Native.FWP_UINT8:  return new V(v.type, v.value.uint8);
                case Native.FWP_UINT16: return new V(v.type, v.value.uint16);
                case Native.FWP_UINT32: return new V(v.type, v.value.uint32);
                case Native.FWP_INT8:   return new V(v.type, unchecked((sbyte)v.value.uint8));
                case Native.FWP_INT16:  return new V(v.type, unchecked((short)v.value.uint16));
                case Native.FWP_INT32:  return new V(v.type, unchecked((int)v.value.uint32));
                case Native.FWP_UINT64:
                case Native.FWP_INT64:
                    return new V(v.type, Marshal.ReadInt64(v.value.ptr));
                case Native.FWP_FLOAT:  return new V(v.type, v.value.float32);
                case Native.FWP_DOUBLE:
                    return new V(v.type, Marshal.PtrToStructure(v.value.ptr, typeof(double)));
                case Native.FWP_BYTE_ARRAY16_TYPE:
                    {
                        byte[] b = new byte[16];
                        Marshal.Copy(v.value.ptr, b, 0, 16);
                        return new V(v.type, b);
                    }
                case Native.FWP_BYTE_BLOB_TYPE:
                    {
                        FWP_BYTE_BLOB blob = (FWP_BYTE_BLOB)Marshal.PtrToStructure(
                            v.value.ptr, typeof(FWP_BYTE_BLOB));
                        if (blob.size == 0 || blob.data == IntPtr.Zero) return new V(v.type, new byte[0]);
                        byte[] b = new byte[blob.size];
                        Marshal.Copy(blob.data, b, 0, (int)blob.size);
                        return new V(v.type, b);
                    }
                case Native.FWP_SECURITY_DESCRIPTOR_TYPE:
                    {
                        // 同为 FWP_BYTE_BLOB 形式
                        FWP_BYTE_BLOB blob = (FWP_BYTE_BLOB)Marshal.PtrToStructure(
                            v.value.ptr, typeof(FWP_BYTE_BLOB));
                        if (blob.size == 0 || blob.data == IntPtr.Zero) return new V(v.type, new byte[0]);
                        byte[] b = new byte[blob.size];
                        Marshal.Copy(blob.data, b, 0, (int)blob.size);
                        return new V(v.type, b);
                    }
                case Native.FWP_SID:
                    {
                        IntPtr strPtr;
                        if (Native.ConvertSidToStringSid(v.value.ptr, out strPtr))
                        {
                            string s = Marshal.PtrToStringUni(strPtr);
                            Native.LocalFree(strPtr);
                            return new V(v.type, s);
                        }
                        return new V(v.type, null);
                    }
                case Native.FWP_UNICODE_STRING_TYPE:
                    return new V(v.type, Str(v.value.ptr));
                case Native.FWP_TOKEN_INFORMATION_TYPE:
                case Native.FWP_TOKEN_ACCESS_INFORMATION_TYPE:
                case Native.FWP_BYTE_ARRAY6_TYPE:
                    {
                        int n = (v.type == Native.FWP_BYTE_ARRAY6_TYPE) ? 6 : 0;
                        if (n == 0) return new V(v.type, null);
                        byte[] b = new byte[n];
                        Marshal.Copy(v.value.ptr, b, 0, n);
                        return new V(v.type, b);
                    }
                case Native.FWP_V4_ADDR_MASK:
                    {
                        FWP_V4_ADDR_AND_MASK m = (FWP_V4_ADDR_AND_MASK)Marshal.PtrToStructure(
                            v.value.ptr, typeof(FWP_V4_ADDR_AND_MASK));
                        return new V(v.type, new uint[] { m.addr, m.mask });
                    }
                case Native.FWP_V6_ADDR_MASK:
                    {
                        // FWP_V6_ADDR_AND_MASK = { UINT8 addr[16]; UINT8 prefixLength; }
                        byte[] b = new byte[17];
                        Marshal.Copy(v.value.ptr, b, 0, 17);
                        return new V(v.type, b);
                    }
                case Native.FWP_RANGE_TYPE:
                    {
                        FWP_RANGE0 r = (FWP_RANGE0)Marshal.PtrToStructure(
                            v.value.ptr, typeof(FWP_RANGE0));
                        CondRange cr = new CondRange();
                        cr.Lo = CopyValue(r.low);
                        cr.Hi = CopyValue(r.high);
                        return new V(v.type, cr);
                    }
                default:
                    return new V(v.type, null);
            }
        }

        internal static FilterInfo CopyFilter(IntPtr p)
        {
            FWPM_FILTER0 f = (FWPM_FILTER0)Marshal.PtrToStructure(p, typeof(FWPM_FILTER0));
            FilterInfo fi = new FilterInfo();
            fi.Id = f.filterId;
            fi.FilterKey = f.filterKey;
            fi.Name = Str(f.displayData.name);
            if (f.providerKey != IntPtr.Zero)
                fi.ProviderKey = (Guid)Marshal.PtrToStructure(f.providerKey, typeof(Guid));
            fi.Desc = Str(f.displayData.description);
            fi.Layer = f.layerKey;
            fi.Sublayer = f.subLayerKey;
            fi.Flags = f.flags;
            fi.Action = f.action.type;
            if (f.weight.type != Native.FWP_EMPTY) fi.Weight = CopyValue(f.weight);
            if (f.effectiveWeight.type == Native.FWP_UINT64 && f.effectiveWeight.value.ptr != IntPtr.Zero)
                fi.EffectiveWeight = (ulong)Marshal.ReadInt64(f.effectiveWeight.value.ptr);
            List<CondInfo> conds = new List<CondInfo>();
            if (f.numFilterConditions > 0 && f.filterCondition != IntPtr.Zero)
            {
                int sz = Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));
                for (int i = 0; i < f.numFilterConditions; i++)
                {
                    IntPtr pc = new IntPtr(f.filterCondition.ToInt64() + i * sz);
                    FWPM_FILTER_CONDITION0 c = (FWPM_FILTER_CONDITION0)Marshal.PtrToStructure(
                        pc, typeof(FWPM_FILTER_CONDITION0));
                    CondInfo ci = new CondInfo();
                    ci.FieldKey = c.fieldKey;
                    ci.MatchType = c.matchType;
                    ci.Value = CopyValue(c.conditionValue);
                    conds.Add(ci);
                }
            }
            fi.Conds = conds;
            return fi;
        }

        internal static LayerInfo CopyLayer(IntPtr p)
        {
            FWPM_LAYER0 l = (FWPM_LAYER0)Marshal.PtrToStructure(p, typeof(FWPM_LAYER0));
            LayerInfo li = new LayerInfo();
            li.Key = l.layerKey;
            li.Name = Str(l.displayData.name);
            li.Desc = Str(l.displayData.description);
            return li;
        }

        internal static SubLayerInfo CopySubLayer(IntPtr p)
        {
            FWPM_SUB_LAYER0 s = (FWPM_SUB_LAYER0)Marshal.PtrToStructure(p, typeof(FWPM_SUB_LAYER0));
            SubLayerInfo si = new SubLayerInfo();
            si.Key = s.subLayerKey;
            si.Name = Str(s.displayData.name);
            si.Weight = s.weight;
            return si;
        }

        public List<FilterInfo> EnumFilters()
        {
            return EnumObjects<FilterInfo>(m_handle,
                delegate(IntPtr e) { IntPtr h; int hr = Native.FwpmFilterCreateEnumHandle0(e, IntPtr.Zero, out h); if (hr != 0) throw new WfpException(hr, "创建过滤器枚举句柄失败。"); return h; },
                delegate(IntPtr e, IntPtr h) { Native.FwpmFilterDestroyEnumHandle0(e, h); },
                delegate(IntPtr e, IntPtr h, uint n, out IntPtr entries, out uint cnt) { int hr = Native.FwpmFilterEnum0(e, h, n, out entries, out cnt); if (hr != 0) throw new WfpException(hr, "枚举过滤器失败。"); return 0; },
                CopyFilter);
        }

        public List<SubLayerInfo> EnumSubLayers()
        {
            return EnumObjects<SubLayerInfo>(m_handle,
                delegate(IntPtr e) { IntPtr h; int hr = Native.FwpmSubLayerCreateEnumHandle0(e, IntPtr.Zero, out h); if (hr != 0) throw new WfpException(hr, "创建子层枚举句柄失败。"); return h; },
                delegate(IntPtr e, IntPtr h) { Native.FwpmSubLayerDestroyEnumHandle0(e, h); },
                delegate(IntPtr e, IntPtr h, uint n, out IntPtr entries, out uint cnt) { int hr = Native.FwpmSubLayerEnum0(e, h, n, out entries, out cnt); if (hr != 0) throw new WfpException(hr, "枚举子层失败。"); return 0; },
                CopySubLayer);
        }

        public List<LayerInfo> EnumLayers()
        {
            return EnumObjects<LayerInfo>(m_handle,
                delegate(IntPtr e) { IntPtr h; int hr = Native.FwpmLayerCreateEnumHandle0(e, IntPtr.Zero, out h); if (hr != 0) throw new WfpException(hr, "创建层枚举句柄失败。"); return h; },
                delegate(IntPtr e, IntPtr h) { Native.FwpmLayerDestroyEnumHandle0(e, h); },
                delegate(IntPtr e, IntPtr h, uint n, out IntPtr entries, out uint cnt) { int hr = Native.FwpmLayerEnum0(e, h, n, out entries, out cnt); if (hr != 0) throw new WfpException(hr, "枚举层失败。"); return 0; },
                CopyLayer);
        }

        public FilterInfo GetFilter(ulong id)
        {
            IntPtr p;
            int hr = Native.FwpmFilterGetById0(m_handle, id, out p);
            if (hr != 0) throw new WfpException(hr, string.Format(
                "未找到 ID 为 {0} 的过滤规则 (FwpmFilterGetById0)。", id));
            try
            {
                return CopyFilter(p);   // 释放前完成深拷贝
            }
            finally
            {
                Native.FwpmFreeMemory0(ref p);
            }
        }

        // 确保持久子层存在 (不存在则创建); 返回 HRESULT
        // 持久 filter 必须引用持久子层, 否则 BFE 返回 FWP_E_LIFETIME_MISMATCH (0x80320016)
        public int EnsureSubLayer(Guid key, string name, ushort weight)
        {
            FWPM_SUB_LAYER0 sl = new FWPM_SUB_LAYER0();
            sl.subLayerKey = key;
            sl.displayData.name = Marshal.StringToHGlobalUni(name);
            sl.flags = Native.FWPM_SUBLAYER_FLAG_PERSISTENT;
            sl.weight = weight;
            try
            {
                int hr = Native.FwpmSubLayerAdd0(m_handle, ref sl, IntPtr.Zero);
                // 0x80320009 = FWP_E_ALREADY_EXISTS, 已存在视为成功
                if ((uint)hr == 0x80320009) hr = 0;
                return hr;
            }
            finally
            {
                Marshal.FreeHGlobal(sl.displayData.name);
            }
        }
    }

    internal class WfpException : Exception
    {
        public int HResultCode;
        public WfpException(int hr, string msg) : base(msg) { HResultCode = hr; }
    }

    // ------------------------------------------------------------------
    // 托管化数据视图 —— BFE 分配的内存 (含结构体、字符串、条件数组) 在调用
    // FwpmFreeMemory0 或下一次枚举后即失效, 因此必须在释放前完成深拷贝。
    // ------------------------------------------------------------------
    internal class V { public uint T; public object O; public V(uint t, object o) { T = t; O = o; } }
    internal class CondRange { public V Lo; public V Hi; }
    internal class CondInfo { public Guid FieldKey; public uint MatchType; public V Value; }
    internal class FilterInfo
    {
        public ulong Id; public Guid FilterKey; public string Name; public string Desc;
        public Guid Layer; public Guid Sublayer; public uint Flags; public uint Action;
        public Guid? ProviderKey;
        public List<CondInfo> Conds;
        public V Weight;              // null = 自动分配
        public ulong EffectiveWeight;  // BFE 计算的生效权重 (64 位)
    }
    internal class LayerInfo { public Guid Key; public string Name; public string Desc; }
    internal class SubLayerInfo { public Guid Key; public string Name; public ushort Weight; }

    // ------------------------------------------------------------------
    // 主程序
    // ------------------------------------------------------------------
    internal static class Program
    {
        private const string ToolSublayerName = "wfpctl rules";

        private static int Main(string[] args)
        {
            try { Console.OutputEncoding = Encoding.UTF8; }
            catch { }

            if (args.Length == 0) { Usage(); return 1; }

            string cmd = args[0].ToLowerInvariant();
            string[] rest = new string[args.Length - 1];
            Array.Copy(args, 1, rest, 0, rest.Length);

            try
            {
                if (cmd == "add")                 return CmdAdd(rest);
                if (cmd == "del" || cmd == "delete") return CmdDel(rest);
                if (cmd == "update" || cmd == "upd") return CmdUpdate(rest);
                if (cmd == "list" || cmd == "ls")   return CmdList(rest);
                if (cmd == "show")                return CmdShow(rest);
                if (cmd == "dump")                return CmdDump(rest);
                if (cmd == "layers")              return CmdLayers();
                if (cmd == "sublayers")           return CmdSubLayers();
                if (cmd == "sublayer-add")        return CmdSubLayerAdd(rest);
                if (cmd == "sublayer-del")        return CmdSubLayerDel(rest);
                if (cmd == "help" || cmd == "--help" || cmd == "-h" || cmd == "/?")
                { Usage(); return 0; }
            }
            catch (WfpException ex)
            {
                Console.Error.WriteLine("错误: " + ex.Message);
                Console.Error.WriteLine("(HRESULT = 0x" + ((uint)ex.HResultCode).ToString("X8") + ")");
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("错误: " + ex.Message);
                return 1;
            }

            Console.Error.WriteLine("未知命令: " + args[0]);
            Usage();
            return 1;
        }

        // ================== add ==================
        private class PortRange { public int lo, hi; public bool present { get { return lo >= 0; } } }

        private static int CmdAdd(string[] a)
        {
            string name = "wfpctl rule";
            string desc = "";
            string layerStr = "connect-v4";
            string sublayerStr = null;
            string action = "permit";   // 默认放行; 阻断需显式 --action block
            int protocol = -1;
            string lportStr = null, rportStr = null;
            List<string> lipList = new List<string>(), ripList = new List<string>();
            string app = null;
            bool boottime = false, volatileFlag = false;
            int weight = -1;   // 过滤器权重 0-15, -1 = BFE 自动分配

            for (int i = 0; i < a.Length; i++)
            {
                string arg = a[i];
                if (arg == "--name" && i + 1 < a.Length) { name = a[++i]; }
                else if (arg == "--desc" && i + 1 < a.Length) { desc = a[++i]; }
                else if (arg == "--layer" && i + 1 < a.Length) { layerStr = a[++i]; }
                else if (arg == "--sublayer" && i + 1 < a.Length) { sublayerStr = a[++i]; }
                else if (arg == "--action" && i + 1 < a.Length) { action = a[++i].ToLowerInvariant(); }
                else if (arg == "--protocol" && i + 1 < a.Length) { protocol = ParseProtocol(a[++i]); }
                else if (arg == "--lport" && i + 1 < a.Length) { lportStr = a[++i]; }
                else if (arg == "--rport" && i + 1 < a.Length) { rportStr = a[++i]; }
                else if (arg == "--lip" && i + 1 < a.Length) { lipList.Add(a[++i]); }
                else if (arg == "--rip" && i + 1 < a.Length) { ripList.Add(a[++i]); }
                else if (arg == "--app" && i + 1 < a.Length) { app = a[++i]; }
                else if (arg == "--boottime") { boottime = true; }
                else if (arg == "--volatile") { volatileFlag = true; }
                else if (arg == "--weight" && i + 1 < a.Length)
                {
                    int w;
                    if (!int.TryParse(a[++i], out w) || w < 0 || w > 15)
                    { Console.Error.WriteLine("add: --weight 须为 0-15 (15 最高优先, 同子层内先评估)。缺省则由 BFE 自动分配。"); return 1; }
                    weight = w;
                }
                else { Console.Error.WriteLine("add: 无法识别的参数 " + arg); return 1; }
            }

            if (protocol < -1) { Console.Error.WriteLine("add: 无效的协议。"); return 1; }

            Guid layer = LayerAlias.Resolve(layerStr);
            if (layer == Guid.Empty)
            {
                Console.Error.WriteLine("add: 无法识别的层 \"" + layerStr + "\"。可用别名:");
                Console.Error.Write(LayerAlias.ListForHelp());
                return 1;
            }

            Guid sublayer = WfpGuids.WfpCtlSublayer;
            if (sublayerStr != null)
            {
                if (sublayerStr == "default") sublayer = WfpGuids.WfpCtlSublayer;
                else
                {
                    sublayer = LayerAlias.Resolve(sublayerStr); // 复用 GUID 解析
                    if (sublayer == Guid.Empty)
                    { Console.Error.WriteLine("add: 无效的子层 GUID: " + sublayerStr); return 1; }
                }
            }

            uint actionType;
            if (action == "block") actionType = Native.FWP_ACTION_BLOCK;
            else if (action == "permit" || action == "allow") actionType = Native.FWP_ACTION_PERMIT;
            else { Console.Error.WriteLine("add: --action 仅支持 block 或 permit。"); return 1; }

            // 端口列表 (逗号分隔多段, 每段可为 单端口 或 起-止 范围)
            List<PortRange> lports = ParsePortList(lportStr);
            List<PortRange> rports = ParsePortList(rportStr);
            if (lports == null || rports == null)
            { Console.Error.WriteLine("add: 无效的端口, 应为 80 / 80-90 / 80,443 形式 (1-65535)。"); return 1; }

            // 多端口组合会展开为多条规则
            int total = lports.Count * rports.Count;
            if (total > 64)
            { Console.Error.WriteLine("add: 端口组合过多 (" + total + " 条), 请分批添加。"); return 1; }

            // app id
            IntPtr appBlob = IntPtr.Zero;
            if (app != null)
            {
                int rc = Native.FwpmGetAppIdFromFileName0(app, out appBlob);
                if (rc != 0)
                {
                    Console.Error.WriteLine("add: 获取应用程序 ID 失败 (0x" + ((uint)rc).ToString("X8") +
                        ")。请确认文件路径存在, 例如 \"C:\\Program Files\\app.exe\"。");
                    return 1;
                }
            }

            uint flags = 0;
            // 注意: BOOTTIME 自身已隐含持久化, 与 PERSISTENT 组合会被 BFE 以
            // FWP_E_INVALID_FLAGS (0x8032001E) 拒绝
            if (boottime) flags = Native.FWPM_FILTER_FLAG_BOOTTIME;
            else if (!volatileFlag) flags = Native.FWPM_FILTER_FLAG_PERSISTENT;

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();

                int hr = Native.FwpmTransactionBegin0(engine.Handle, 0);
                if (hr != 0) throw new WfpException(hr, "开始事务失败。");

                bool ok = false;
                List<IntPtr> allocs = new List<IntPtr>();
                List<ulong> addedIds = new List<ulong>();
                try
                {
                    hr = engine.EnsureSubLayer(sublayer, sublayer == WfpGuids.WfpCtlSublayer ? ToolSublayerName : "wfpctl sublayer", 0x100);
                    if (hr != 0) throw new WfpException(hr, "创建子层失败。");

                    int seq = 0;
                    foreach (PortRange lp in lports)
                    {
                        foreach (PortRange rp in rports)
                        {
                            seq++;
                            string fname = (total > 1)
                                ? string.Format("{0} #{1}", name, seq)
                                : name;
                            ulong id;
                            hr = AddOneFilter(engine, allocs, layer, sublayer, actionType, flags,
                                protocol, weight, fname, desc, lp, rp, lipList, ripList, appBlob, out id);
                            if (hr != 0) throw new WfpException(hr,
                                string.Format("添加规则 #{0} 失败 (FwpmFilterAdd0)。", seq));
                            addedIds.Add(id);
                        }
                    }

                    hr = Native.FwpmTransactionCommit0(engine.Handle);
                    if (hr != 0) throw new WfpException(hr, "提交事务失败。");
                    ok = true;
                }
                finally
                {
                    if (!ok) Native.FwpmTransactionAbort0(engine.Handle);
                    foreach (IntPtr p in allocs) Marshal.FreeHGlobal(p);
                    if (appBlob != IntPtr.Zero) { IntPtr t = appBlob; Native.FwpmFreeMemory0(ref t); }
                }

                foreach (ulong id in addedIds)
                    Console.WriteLine(string.Format("已添加规则, ID = {0}  名称 = {1}", id, name));
                if (boottime) Console.WriteLine("提示: 该规则为启动时间规则 (BFE 未启动时即生效)。");
                Console.WriteLine("提示: 使用 \"wfpctl list\" 查看, \"wfpctl del <ID>\" 删除。");
                return 0;
            }
        }

        // ================== update ==================
        // WFP 无原地修改 API, 采用事务内“删旧+建新”; 未指定的参数保持原值; any 清除条件
        private static int CmdUpdate(string[] a)
        {
            if (a.Length == 0)
            { Console.Error.WriteLine("用法: wfpctl update <规则ID> [参数]。未指定的参数保持原值; any 清除条件。"); return 1; }
            ulong fid;
            if (!ulong.TryParse(a[0], out fid))
            { Console.Error.WriteLine("update: 无效的规则 ID: " + a[0]); return 1; }

            // 用户覆盖参数 (null/-2 = 未指定)
            string name = null, desc = null, layerStr = null, sublayerStr = null;
            string action = null;
            int protocol = -2;
            string lportStr = null, rportStr = null;
            List<string> lipList = null, ripList = null;
            bool hasLip = false, hasRip = false, hasLport = false, hasRport = false, hasApp = false;
            string app = null;
            int weightSet = -1;          // -1=未指定 0=auto 1=指定
            int weight = 0;
            int boottime = -1, volatileFlag = -1;

            for (int i = 1; i < a.Length; i++)
            {
                string arg = a[i];
                if (arg == "--name" && i + 1 < a.Length) name = a[++i];
                else if (arg == "--desc" && i + 1 < a.Length) desc = a[++i];
                else if (arg == "--action" && i + 1 < a.Length)
                {
                    action = a[++i].ToLowerInvariant();
                    if (action != "block" && action != "permit" && action != "allow")
                    { Console.Error.WriteLine("update: --action 仅支持 block 或 permit。"); return 1; }
                }
                else if (arg == "--protocol" && i + 1 < a.Length)
                {
                    protocol = ParseProtocol(a[++i]);
                    if (protocol < -1) { Console.Error.WriteLine("update: 无效的协议。"); return 1; }
                }
else if (arg == "--lip" && i + 1 < a.Length)
                {
                    hasLip = true;
                    string v = a[++i];
                    if (v.ToLowerInvariant() == "any") lipList = null;
                    else { if (lipList == null) lipList = new List<string>(); lipList.Add(v); }
                }
                else if (arg == "--rip" && i + 1 < a.Length)
                {
                    hasRip = true;
                    string v = a[++i];
                    if (v.ToLowerInvariant() == "any") ripList = null;
                    else { if (ripList == null) ripList = new List<string>(); ripList.Add(v); }
                }
                else if (arg == "--lport" && i + 1 < a.Length)
                { hasLport = true; lportStr = (a[++i].ToLowerInvariant() == "any") ? null : a[i]; }
                else if (arg == "--rport" && i + 1 < a.Length)
                { hasRport = true; rportStr = (a[++i].ToLowerInvariant() == "any") ? null : a[i]; }
                else if (arg == "--app" && i + 1 < a.Length)
                { hasApp = true; app = (a[++i].ToLowerInvariant() == "any") ? null : a[i]; }
                else if (arg == "--weight" && i + 1 < a.Length)
                {
                    string w = a[++i];
                    if (w.ToLowerInvariant() == "auto") weightSet = 0;
                    else
                    {
                        if (!int.TryParse(w, out weight) || weight < 0 || weight > 15)
                        { Console.Error.WriteLine("update: --weight 须为 0-15 或 auto。"); return 1; }
                        weightSet = 1;
                    }
                }
                else if (arg == "--boottime") boottime = 1;
                else if (arg == "--volatile") volatileFlag = 1;
                else if (arg == "--persistent") volatileFlag = 0;
                else if (arg == "--layer" && i + 1 < a.Length) layerStr = a[++i];
                else if (arg == "--sublayer" && i + 1 < a.Length) sublayerStr = a[++i];
                else { Console.Error.WriteLine("update: 无法识别的参数 " + arg); return 1; }
            }

            if (boottime == 1 && volatileFlag == 1)
            { Console.Error.WriteLine("update: --boottime 与 --volatile 互斥。"); return 1; }

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                FilterInfo f;
                try { f = engine.GetFilter(fid); }
                catch (WfpException)
                { Console.Error.WriteLine("update: 未找到 ID 为 " + fid + " 的规则。"); return 1; }
                if (f.Action != Native.FWP_ACTION_BLOCK && f.Action != Native.FWP_ACTION_PERMIT)
                { Console.Error.WriteLine("update: 仅支持修改 BLOCK/PERMIT 动作的规则。"); return 1; }

                // ---- 提取基值 ----
                string bName = f.Name ?? "wfpctl rule";
                string bDesc = f.Desc ?? "";
                bool bActionBlock = (f.Action == Native.FWP_ACTION_BLOCK);
                Guid bLayer = f.Layer, bSublayer = f.Sublayer;
                bool bBoottime = (f.Flags & Native.FWPM_FILTER_FLAG_BOOTTIME) != 0;
                bool bVolatile = !bBoottime && (f.Flags & Native.FWPM_FILTER_FLAG_PERSISTENT) == 0;
                bool bWeightSet = (f.Weight != null && f.Weight.T == Native.FWP_UINT8);
                int bWeight = bWeightSet ? (byte)(object)f.Weight.O : 0;
                int bProto = -1;
                string bLip = null, bRip = null, bLport = null, bRport = null;
                byte[] bAppBytes = null;
                bool bHasApp = false;
                foreach (CondInfo c in f.Conds)
                {
                    if (c.FieldKey == WfpGuids.CondIpProtocol)
                    { if (c.Value != null && c.Value.T == Native.FWP_UINT8) bProto = (byte)(object)c.Value.O; }
                    else if (c.FieldKey == WfpGuids.CondIpLocalAddr)
{ bLip = RenderValue(c.Value, false, true); }
                    else if (c.FieldKey == WfpGuids.CondIpRemoteAddr)
                    { bRip = RenderValue(c.Value, false, true); }
                    else if (c.FieldKey == WfpGuids.CondIpLocalPort)
                    { bLport = RenderValue(c.Value, true, false).Replace(" ~ ", "-"); }
                    else if (c.FieldKey == WfpGuids.CondIpRemotePort)
                    { bRport = RenderValue(c.Value, true, false).Replace(" ~ ", "-"); }
                    else if (c.FieldKey == WfpGuids.CondAleAppId)
                    {
                        if (c.Value != null && c.Value.T == Native.FWP_BYTE_BLOB_TYPE && c.Value.O is byte[])
                        { bAppBytes = (byte[])(object)c.Value.O; bHasApp = bAppBytes.Length > 0; }
                    }
                    else
                    {
                        Console.Error.WriteLine("update: 该规则含本工具无法编辑的条件 (" + FieldName(c.FieldKey) + "), 请删除后重新添加。");
                        return 1;
                    }
                }

                // ---- 合成 (用户覆盖 > 旧值) ----
                string fName = name ?? bName;
                string fDesc = desc ?? bDesc;
                bool fActionBlock = (action == null) ? bActionBlock : (action == "block");
                int fProto = (protocol == -2) ? bProto : protocol;
                Guid fLayer, fSublayer;
                if (layerStr != null)
                {
                    fLayer = LayerAlias.Resolve(layerStr);
                    if (fLayer == Guid.Empty)
                    { Console.Error.WriteLine("update: 无法识别的层 \"" + layerStr + "\"。"); return 1; }
                }
                else fLayer = bLayer;
                if (sublayerStr != null)
                {
                    fSublayer = (sublayerStr == "default") ? WfpGuids.WfpCtlSublayer : LayerAlias.Resolve(sublayerStr);
                    if (fSublayer == Guid.Empty)
                    { Console.Error.WriteLine("update: 无效的子层 GUID: " + sublayerStr); return 1; }
                }
                else fSublayer = bSublayer;
                bool fBoottime = (boottime == -1) ? bBoottime : (boottime == 1);
                bool fVolatile = (volatileFlag == -1) ? bVolatile : (volatileFlag == 1);
                int fWeightSet = (weightSet == -1) ? (bWeightSet ? 1 : 0) : weightSet;
                int fWeight = (weightSet == -1) ? bWeight : weight;

                // app
                IntPtr userAppBlob = IntPtr.Zero;
                IntPtr appBlob = IntPtr.Zero;
                bool hasAppFinal;
                if (hasApp)
                {
                    if (app != null)
                    {
                        int rc = Native.FwpmGetAppIdFromFileName0(app, out userAppBlob);
                        if (rc != 0)
                        {
                            Console.Error.WriteLine("update: 获取应用程序 ID 失败 (0x" + ((uint)rc).ToString("X8") + ")。请确认文件路径存在。");
                            return 1;
                        }
                        appBlob = userAppBlob;
                        hasAppFinal = true;
                    }
                    else hasAppFinal = false;
                }
                else hasAppFinal = bHasApp;

                // lip/rip (支持多个)
                List<string> fLipList, fRipList;
                bool fHasLip, fHasRip;
                if (hasLip) { fHasLip = (lipList != null && lipList.Count > 0); fLipList = lipList; }
                else { fHasLip = (bLip != null); fLipList = (bLip != null) ? new List<string> { bLip } : null; }
                if (hasRip) { fHasRip = (ripList != null && ripList.Count > 0); fRipList = ripList; }
                else { fHasRip = (bRip != null); fRipList = (bRip != null) ? new List<string> { bRip } : null; }

                // lport/rport
                PortRange fLp = new PortRange { lo = -1, hi = -1 };
                PortRange fRp = new PortRange { lo = -1, hi = -1 };
                if (hasLport && lportStr != null)
                {
                    List<PortRange> pl = ParsePortList(lportStr);
                    if (pl == null || pl.Count != 1)
                    { Console.Error.WriteLine("update: 每次只修改一条规则, --lport 仅接受单端口或单范围 (如 80 / 80-90)。"); return 1; }
                    fLp = pl[0];
                }
                else if (!hasLport && bLport != null)
                {
                    List<PortRange> pl = ParsePortList(bLport);
                    if (pl == null || pl.Count != 1)
                    { Console.Error.WriteLine("update: 原规则的端口条件无法解析。"); return 1; }
                    fLp = pl[0];
                }
                if (hasRport && rportStr != null)
                {
                    List<PortRange> pl = ParsePortList(rportStr);
                    if (pl == null || pl.Count != 1)
                    { Console.Error.WriteLine("update: 每次只修改一条规则, --rport 仅接受单端口或单范围 (如 80 / 80-90)。"); return 1; }
                    fRp = pl[0];
                }
                else if (!hasRport && bRport != null)
                {
                    List<PortRange> pl = ParsePortList(bRport);
                    if (pl == null || pl.Count != 1)
                    { Console.Error.WriteLine("update: 原规则的端口条件无法解析。"); return 1; }
                    fRp = pl[0];
                }

                // 从旧字节重建 app blob (用户未指定新 app 时保留旧 app)
                List<IntPtr> allocs = new List<IntPtr>();
                if (hasAppFinal && appBlob == IntPtr.Zero && bAppBytes != null)
                {
                    IntPtr dataPtr = Marshal.AllocHGlobal(bAppBytes.Length);
                    allocs.Add(dataPtr);
                    Marshal.Copy(bAppBytes, 0, dataPtr, bAppBytes.Length);
                    IntPtr blobPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWP_BYTE_BLOB)));
                    allocs.Add(blobPtr);
                    FWP_BYTE_BLOB bb = new FWP_BYTE_BLOB();
                    bb.size = (uint)bAppBytes.Length;
                    bb.data = dataPtr;
                    Marshal.StructureToPtr(bb, blobPtr, false);
                    appBlob = blobPtr;
                }

                uint fFlags = 0;
                if (fBoottime) fFlags = Native.FWPM_FILTER_FLAG_BOOTTIME;
                else if (!fVolatile) fFlags = Native.FWPM_FILTER_FLAG_PERSISTENT;
                uint fActionType = fActionBlock ? Native.FWP_ACTION_BLOCK : Native.FWP_ACTION_PERMIT;

                // ---- 事务: 删旧 + 建新 ----
                int hr = Native.FwpmTransactionBegin0(engine.Handle, 0);
                if (hr != 0) throw new WfpException(hr, "开始事务失败。");
                bool ok = false;
                ulong newId = 0;
                try
                {
                    hr = Native.FwpmFilterDeleteById0(engine.Handle, fid);
                    if (hr != 0) throw new WfpException(hr, string.Format("删除旧规则 {0} 失败。", fid));

                    hr = AddOneFilter(engine, allocs, fLayer, fSublayer, fActionType, fFlags,
                        fProto, (fWeightSet == 1) ? fWeight : -1, fName, fDesc,
                        fLp, fRp, fHasLip ? fLipList : null, fHasRip ? fRipList : null, appBlob, out newId);
                    if (hr != 0) throw new WfpException(hr, "重建规则失败 (FwpmFilterAdd0)。");

                    hr = Native.FwpmTransactionCommit0(engine.Handle);
                    if (hr != 0) throw new WfpException(hr, "提交事务失败。");
                    ok = true;
                }
                finally
                {
                    if (!ok) Native.FwpmTransactionAbort0(engine.Handle);
                    foreach (IntPtr p in allocs) Marshal.FreeHGlobal(p);
                    if (userAppBlob != IntPtr.Zero) { IntPtr t = userAppBlob; Native.FwpmFreeMemory0(ref t); }
                }

                Console.WriteLine(string.Format("已修改规则: ID {0} → {1}  名称 = {2}", fid, newId, fName));
                return 0;
            }
        }

        private static int AddOneFilter(WfpEngine engine, List<IntPtr> allocs, Guid layer,
            Guid sublayer, uint actionType, uint flags, int protocol, int weight, string name, string desc,
            PortRange lp, PortRange rp, List<string> lips, List<string> rips, IntPtr appBlob, out ulong outId)
        {
            List<FWPM_FILTER_CONDITION0> conds = new List<FWPM_FILTER_CONDITION0>();

            if (protocol >= 0)
            {
                FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
                c.fieldKey = WfpGuids.CondIpProtocol;
                c.matchType = Native.FWP_MATCH_EQUAL;
                c.conditionValue.type = Native.FWP_UINT8;
                c.conditionValue.value.uint8 = (byte)protocol;
                conds.Add(c);
            }
            if (lips != null)
                foreach (string s in lips)
                    AddIpCondition(conds, allocs, WfpGuids.CondIpLocalAddr, s);
            if (rips != null)
                foreach (string s in rips)
                    AddIpCondition(conds, allocs, WfpGuids.CondIpRemoteAddr, s);
            if (lp.present) AddPortCondition(conds, allocs, WfpGuids.CondIpLocalPort, lp);
            if (rp.present) AddPortCondition(conds, allocs, WfpGuids.CondIpRemotePort, rp);
            if (appBlob != IntPtr.Zero)
            {
                FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
                c.fieldKey = WfpGuids.CondAleAppId;
                c.matchType = Native.FWP_MATCH_EQUAL;
                c.conditionValue.type = Native.FWP_BYTE_BLOB_TYPE;
                c.conditionValue.value.ptr = appBlob;
                conds.Add(c);
            }

            FWPM_FILTER0 f = new FWPM_FILTER0();
            f.layerKey = layer;
            f.subLayerKey = sublayer;
            f.flags = flags;
            if (weight >= 0)
            {
                // 显式权重: 同子层内权重高的先评估, 遇到第一条 BLOCK/PERMIT 即定案
                f.weight.type = Native.FWP_UINT8;
                f.weight.value.uint8 = (byte)weight;
            }
            f.action.type = actionType;
            f.numFilterConditions = (uint)conds.Count;

            f.displayData.name = Marshal.StringToHGlobalUni(name);
            f.displayData.description = Marshal.StringToHGlobalUni(desc);
            allocs.Add(f.displayData.name);
            allocs.Add(f.displayData.description);

            IntPtr condBuf = IntPtr.Zero;
            if (conds.Count > 0)
            {
                // 写入(add)时用 CLR 默认间距 (Marshal.SizeOf = 40), BFE 接收时按此间距读取
                int sz = Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));
                condBuf = Marshal.AllocHGlobal(sz * conds.Count);
                allocs.Add(condBuf);
                for (int i = 0; i < conds.Count; i++)
                {
                    IntPtr p = new IntPtr(condBuf.ToInt64() + i * sz);
                    Marshal.StructureToPtr(conds[i], p, false);
                }
                f.filterCondition = condBuf;
            }

            ulong id;
            int hr = Native.FwpmFilterAdd0(engine.Handle, ref f, IntPtr.Zero, out id);
            outId = id;
            return hr;
        }

        private static int ParseProtocol(string s)
        {
            switch (s.ToLowerInvariant())
            {
                case "tcp": return 6;
                case "udp": return 17;
                case "icmp": return 1;
                case "icmpv6": return 58;
                case "any": return -1;
                default:
                    int n;
                    if (int.TryParse(s, out n) && n >= 0 && n <= 255) return n;
                    return -2;
            }
        }

        private static List<PortRange> ParsePortList(string s)
        {
            List<PortRange> list = new List<PortRange>();
            if (s == null)
            {
                list.Add(new PortRange { lo = -1, hi = -1 });
                return list;
            }
            string[] parts = s.Split(',');
            if (parts.Length > 16) return null;
            foreach (string part in parts)
            {
                string p = part.Trim();
                PortRange pr = new PortRange();
                int dash = p.IndexOf('-');
                if (dash >= 0)
                {
                    int lo, hi;
                    if (!int.TryParse(p.Substring(0, dash).Trim(), out lo) ||
                        !int.TryParse(p.Substring(dash + 1).Trim(), out hi)) return null;
                    if (lo < 1 || hi < lo || hi > 65535) return null;
                    pr.lo = lo; pr.hi = hi;
                }
                else
                {
                    int v;
                    if (!int.TryParse(p, out v) || v < 1 || v > 65535) return null;
                    pr.lo = v; pr.hi = v;
                }
                list.Add(pr);
            }
            return list;
        }

        // 端口条件: 端口/地址等数值一律使用网络字节序
        private static void AddPortCondition(List<FWPM_FILTER_CONDITION0> conds,
            List<IntPtr> allocs, Guid field, PortRange pr)
        {
            FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
            c.fieldKey = field;
            if (pr.lo == pr.hi)
            {
                c.matchType = Native.FWP_MATCH_EQUAL;
                c.conditionValue.type = Native.FWP_UINT16;
                c.conditionValue.value.uint16 = (ushort)pr.lo;
            }
            else
            {
                // 端口范围: BFE 以主机字节序比较, low < high 即可
                ushort nlo = (ushort)pr.lo;
                ushort nhi = (ushort)pr.hi;
                if (nlo > nhi)
                    throw new Exception(string.Format(
                        "端口范围 {0}-{1} 无效 (起大于止)。",
                        pr.lo, pr.hi));
                c.matchType = Native.FWP_MATCH_RANGE;
                c.conditionValue.type = Native.FWP_RANGE_TYPE;
                IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWP_RANGE0)));
                allocs.Add(p);
                FWP_RANGE0 r = new FWP_RANGE0();
                r.low.type = Native.FWP_UINT16;  r.low.value.uint16 = nlo;
                r.high.type = Native.FWP_UINT16; r.high.value.uint16 = nhi;
                Marshal.StructureToPtr(r, p, false);
                c.conditionValue.value.ptr = p;
            }
            conds.Add(c);
        }

        // IP 条件: 支持 IPv4/IPv6, 支持前缀长度(24)与子网掩码(255.255.0.0)两种写法
        private static void AddIpCondition(List<FWPM_FILTER_CONDITION0> conds,
            List<IntPtr> allocs, Guid field, string spec)
        {
            string ipStr = spec;
            string maskStr = null;
            int slash = spec.IndexOf('/');
            if (slash >= 0)
            {
                ipStr = spec.Substring(0, slash);
                maskStr = spec.Substring(slash + 1);
            }

            IPAddress ip;
            if (!IPAddress.TryParse(ipStr, out ip))
                throw new Exception("无法解析 IP 地址: " + ipStr);

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                // FWP_V4_ADDR_AND_MASK.addr 为网络字节序数值: 0xAABBCCDD 即 A.B.C.D
                byte[] ba = ip.GetAddressBytes();
                uint addr = (uint)((int)ba[0] << 24 | (int)ba[1] << 16 |
                                   (int)ba[2] << 8 | (int)ba[3]);
                uint mask = 0xFFFFFFFF;
                if (maskStr != null)
                {
                    int prefix;
                    if (int.TryParse(maskStr, out prefix))
                    {
                        if (prefix < 0 || prefix > 32) throw new Exception("无效的前缀长度: " + maskStr);
                        mask = (prefix == 0) ? 0u : (uint)(0xFFFFFFFF << (32 - prefix));
                    }
                    else
                    {
                        IPAddress m;
                        if (!IPAddress.TryParse(maskStr, out m) ||
                            m.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                            throw new Exception("无法解析掩码: " + maskStr);
                        byte[] mb = m.GetAddressBytes();
                        mask = (uint)((int)mb[0] << 24 | (int)mb[1] << 16 |
                                      (int)mb[2] << 8 | (int)mb[3]);
                    }
                }
                IntPtr p = Marshal.AllocHGlobal(8);
                allocs.Add(p);
                Marshal.WriteInt32(p, 0, unchecked((int)addr));
                Marshal.WriteInt32(p, 4, unchecked((int)mask));

                FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
                c.fieldKey = field;
                c.matchType = Native.FWP_MATCH_EQUAL;
                c.conditionValue.type = Native.FWP_V4_ADDR_MASK;
                c.conditionValue.value.ptr = p;
                conds.Add(c);
            }
            else
            {
                byte[] addr6 = ip.GetAddressBytes();
                int prefix = 128;   // 未指定掩码 = 单地址
                if (maskStr != null)
                {
                    if (!int.TryParse(maskStr, out prefix) || prefix < 0 || prefix > 128)
                        throw new Exception("无效的前缀长度: " + maskStr);
                }
                // FWP_V6_ADDR_AND_MASK = { UINT8 addr[16]; UINT8 prefixLength; } 共 17 字节
                IntPtr p = Marshal.AllocHGlobal(17);
                allocs.Add(p);
                for (int i = 0; i < 16; i++) Marshal.WriteByte(p, i, addr6[i]);
                Marshal.WriteByte(p, 16, (byte)prefix);

                FWPM_FILTER_CONDITION0 c = new FWPM_FILTER_CONDITION0();
                c.fieldKey = field;
                c.matchType = Native.FWP_MATCH_EQUAL;
                c.conditionValue.type = Native.FWP_V6_ADDR_MASK;
                c.conditionValue.value.ptr = p;
                conds.Add(c);
            }
        }

        private static ushort HostToNetwork(int host)
        {
            return (ushort)IPAddress.HostToNetworkOrder((short)host);
        }

        private static ushort NetworkToHost(ushort net)
        {
            return (ushort)IPAddress.NetworkToHostOrder((short)net);
        }

        // ================== list ==================
        private static int CmdList(string[] a)
        {
            bool all = false;
            Guid layerFilter = Guid.Empty;
            Guid sublayerFilter = Guid.Empty;
            string sublayerName = null;   // 按名称匹配时暂存, 引擎打开后解析
            List<Guid> sublayerSet = null;
            string nameFilter = null;
            int actionFilter = 0;      // 0=不过滤 1=BLOCK 2=PERMIT

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == "--all") all = true;
                else if (a[i] == "--name" && i + 1 < a.Length) nameFilter = a[++i];
                else if (a[i] == "--action" && i + 1 < a.Length)
                {
                    string act = a[++i].ToLowerInvariant();
                    if (act == "block") actionFilter = 1;
                    else if (act == "permit" || act == "allow") actionFilter = 2;
                    else { Console.Error.WriteLine("list: --action 仅支持 block 或 permit。"); return 1; }
                }
                else if (a[i] == "--layer" && i + 1 < a.Length)
                {
                    layerFilter = LayerAlias.Resolve(a[++i]);
                    if (layerFilter == Guid.Empty)
                    { Console.Error.WriteLine("list: 无法识别的层: " + a[i]); return 1; }
                }
                else if (a[i] == "--sublayer" && i + 1 < a.Length)
                {
                    string v = a[++i];
                    if (v == "default") sublayerFilter = WfpGuids.WfpCtlSublayer;
                    else
                    {
                        sublayerFilter = LayerAlias.Resolve(v);
                        if (sublayerFilter == Guid.Empty)
                        {
                            // 不是 GUID → 视为子层名称, 引擎打开后枚举匹配
                            if (v.Length == 0)
                            { Console.Error.WriteLine("list: --sublayer 需要子层 GUID、名称或 default。"); return 1; }
                            sublayerName = v;
                        }
                    }
                }
                else { Console.Error.WriteLine("list: 无法识别的参数 " + a[i]); return 1; }
            }

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();

                // --sublayer 传的是名称时: 枚举子层做大小写不敏感子串匹配
                if (sublayerName != null)
                {
                    sublayerSet = new List<Guid>();
                    foreach (SubLayerInfo s in engine.EnumSubLayers())
                    {
                        if (s.Name != null &&
                            s.Name.IndexOf(sublayerName, StringComparison.OrdinalIgnoreCase) >= 0)
                            sublayerSet.Add(s.Key);
                    }
                    if (sublayerSet.Count == 0)
                    {
                        Console.Error.WriteLine("list: 未找到名称含 \"" + sublayerName +
                            "\" 的子层。可用 \"wfpctl sublayers\" 查看全部子层及其 GUID。");
                        return 1;
                    }
                }

                List<FilterInfo> filters = engine.EnumFilters();

                if (sublayerName != null && sublayerSet.Count > 1)
                    Console.WriteLine("按子层名称 \"" + sublayerName + "\" 匹配到 " + sublayerSet.Count + " 个子层:");

                Console.WriteLine();
                Console.WriteLine("ID".PadRight(12) + "动作".PadRight(10) + "层".PadRight(16) +
                    "标志".PadRight(8) + "名称");
                Console.WriteLine(new string('-', 78));

                int shown = 0, total = 0;
                foreach (FilterInfo f in filters)
                {
                    total++;
                    if (sublayerName != null)
                    {
                        if (!sublayerSet.Contains(f.Sublayer)) continue;
                    }
                    else if (sublayerFilter != Guid.Empty)
                    {
                        if (f.Sublayer != sublayerFilter) continue;
                    }
                    else if (!all && f.Sublayer != WfpGuids.WfpCtlSublayer) continue;
                    if (layerFilter != Guid.Empty && f.Layer != layerFilter) continue;
                    if (actionFilter == 1 && f.Action != Native.FWP_ACTION_BLOCK) continue;
                    if (actionFilter == 2 && f.Action != Native.FWP_ACTION_PERMIT) continue;
                    if (nameFilter != null)
                    {
                        string nm = (f.Name ?? "").ToLowerInvariant();
                        string ds = (f.Desc ?? "").ToLowerInvariant();
                        if (nm.IndexOf(nameFilter.ToLowerInvariant(), StringComparison.Ordinal) < 0 &&
                            ds.IndexOf(nameFilter.ToLowerInvariant(), StringComparison.Ordinal) < 0) continue;
                    }
                    shown++;

                    string layerName = LayerAlias.AliasOf(f.Layer);
                    if (layerName == null) layerName = f.Layer.ToString("D").Substring(0, 13) + "..";

                    string actionName;
                    if (f.Action == Native.FWP_ACTION_BLOCK) actionName = "BLOCK";
                    else if (f.Action == Native.FWP_ACTION_PERMIT) actionName = "PERMIT";
                    else if ((f.Action & 0x00004000) != 0) actionName = "CALLOUT";
                    else actionName = "0x" + f.Action.ToString("X");

                    StringBuilder fl = new StringBuilder();
                    if ((f.Flags & Native.FWPM_FILTER_FLAG_PERSISTENT) != 0) fl.Append('P');
                    if ((f.Flags & Native.FWPM_FILTER_FLAG_BOOTTIME) != 0) fl.Append('B');
                    if ((f.Flags & Native.FWPM_FILTER_FLAG_DISABLED) != 0) fl.Append('D');
                    if ((f.Flags & Native.FWPM_FILTER_FLAG_INDEXED) != 0) fl.Append('I');
                    if (fl.Length == 0) fl.Append('-');

                    Console.WriteLine(f.Id.ToString().PadRight(12) +
                        actionName.PadRight(10) + layerName.PadRight(16) +
                        fl.ToString().PadRight(8) + (f.Name ?? "<无名>"));
                }

                Console.WriteLine(new string('-', 78));
                if (all || nameFilter != null || actionFilter != 0 || sublayerFilter != Guid.Empty || sublayerName != null)
                    Console.WriteLine("共 " + total + " 条规则 (系统全部), 匹配显示 " + shown + " 条");
                else
                    Console.WriteLine("共 " + total + " 条规则 (系统全部), 本工具创建 " + shown +
                        " 条。加 --all 查看系统全部规则");
            }
            return 0;
        }

        // ================== show ==================
        private static int CmdShow(string[] a)
        {
            if (a.Length != 1)
            { Console.Error.WriteLine("用法: wfpctl show <规则ID>"); return 1; }
            ulong id;
            if (!ulong.TryParse(a[0], out id))
            { Console.Error.WriteLine("show: 规则 ID 必须是数字 (可先用 list 查看)。"); return 1; }

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                FilterInfo f = engine.GetFilter(id);

                // 建立 GUID -> 名称 映射, 输出更友好
                Dictionary<Guid, string> layerNames = new Dictionary<Guid, string>();
                foreach (LayerInfo l in engine.EnumLayers())
                {
                    if (l.Name != null && !layerNames.ContainsKey(l.Key)) layerNames[l.Key] = l.Name;
                }
                Dictionary<Guid, string> subNames = new Dictionary<Guid, string>();
                foreach (SubLayerInfo s in engine.EnumSubLayers())
                {
                    if (s.Name != null && !subNames.ContainsKey(s.Key)) subNames[s.Key] = s.Name;
                }

                string layerAlias = LayerAlias.AliasOf(f.Layer);
                string bfeLayerName;
                layerNames.TryGetValue(f.Layer, out bfeLayerName);
                string subName;
                subNames.TryGetValue(f.Sublayer, out subName);

                Console.WriteLine();
                Console.WriteLine("规则 ID        : " + f.Id);
                Console.WriteLine("规则 Key       : {" + f.FilterKey + "}");
                Console.WriteLine("名称           : " + (f.Name ?? ""));
                Console.WriteLine("描述           : " + (f.Desc ?? ""));
                if (f.ProviderKey.HasValue)
                {
                    string pName = GetProviderName(engine, f.ProviderKey.Value);
                    Console.WriteLine("提供者         : {" + f.ProviderKey.Value + "}" +
                        (pName != null ? "  (" + pName + ")" : ""));
                }
                Console.WriteLine("层             : {" + f.Layer + "}" +
                    (layerAlias != null ? "  别名 " + layerAlias : "") +
                    (bfeLayerName != null ? "  (" + bfeLayerName + ")" : ""));
                Console.WriteLine("子层           : {" + f.Sublayer + "}" +
                    (subName != null ? "  (" + subName + ")" : ""));
                Console.WriteLine("标志           : 0x" + f.Flags.ToString("X") +
                    ((f.Flags & Native.FWPM_FILTER_FLAG_PERSISTENT) != 0 ? "  [持久]" : "") +
                    ((f.Flags & Native.FWPM_FILTER_FLAG_BOOTTIME) != 0 ? "  [启动时]" : "") +
                    ((f.Flags & Native.FWPM_FILTER_FLAG_DISABLED) != 0 ? "  [已禁用]" : "") +
                    ((f.Flags & Native.FWPM_FILTER_FLAG_INDEXED) != 0 ? "  [已索引]" : ""));
                string persistInfo;
                if ((f.Flags & Native.FWPM_FILTER_FLAG_BOOTTIME) != 0)
                    persistInfo = "是 (启动时规则, BFE 启动阶段即生效, 重启后仍在)";
                else if ((f.Flags & Native.FWPM_FILTER_FLAG_PERSISTENT) != 0)
                    persistInfo = "是 (重启后仍生效)";
                else if (f.Sublayer == WfpGuids.WfpCtlSublayer)
                    persistInfo = "否 (临时规则, BFE 服务重启后消失)";
                else
                    persistInfo = "否 (非持久; 但属系统/外部服务规则, 如 Windows 防火墙规则, 其服务启动时自动重建)";
                Console.WriteLine("持久化         : " + persistInfo);

                string actionName;
                if (f.Action == Native.FWP_ACTION_BLOCK) actionName = "BLOCK (阻断)";
                else if (f.Action == Native.FWP_ACTION_PERMIT) actionName = "PERMIT (放行)";
                else actionName = "0x" + f.Action.ToString("X");
                Console.WriteLine("动作           : " + actionName);

                string wstr = (f.Weight == null || f.Weight.O == null) ? "自动"
                    : RenderValue(f.Weight, false, false);
                Console.WriteLine("权重           : " + wstr +
                    (f.EffectiveWeight != 0
                        ? "  (生效权重 0x" + f.EffectiveWeight.ToString("X16") + ", 同子层内值大者优先评估)"
                        : ""));

                List<CondInfo> conds = f.Conds;
                Console.WriteLine("匹配条件       : " + conds.Count + " 个" + (conds.Count == 0 ? " (匹配全部流量)" : ""));
                for (int i = 0; i < conds.Count; i++)
                {
                    CondInfo c = conds[i];
                    Console.WriteLine("  [" + (i + 1) + "] " + FieldName(c.FieldKey).PadRight(10) +
                        " " + MatchName(c.MatchType) + "  " + TypeName(c.Value) + "  " + FormatCondValue(c));
                }
                Console.WriteLine();
            }
            return 0;
        }

        // ================== dump ==================
        private static int CmdDump(string[] a)
        {
            ulong id = 0; string nameFilter = null; bool byId = false;
            if (a.Length == 1 && a[0] != "--name")
            {
                if (!ulong.TryParse(a[0], out id)) { Console.Error.WriteLine("dump: 规则 ID 必须是数字 (可先用 list 查看)。"); return 1; }
                byId = true;
            }
            else if (a.Length == 2 && a[0] == "--name") nameFilter = a[1];
            else { Console.Error.WriteLine("用法: wfpctl dump <规则ID>   或   wfpctl dump --name <关键字>"); return 1; }

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                List<FilterInfo> list = new List<FilterInfo>();
                if (byId) list.Add(engine.GetFilter(id));
                else
                {
                    foreach (FilterInfo f in engine.EnumFilters())
                    {
                        if ((f.Name != null && f.Name.IndexOf(nameFilter, StringComparison.OrdinalIgnoreCase) >= 0) ||
                            (f.Desc != null && f.Desc.IndexOf(nameFilter, StringComparison.OrdinalIgnoreCase) >= 0))
                            list.Add(f);
                    }
                }
                if (list.Count == 0) { Console.Error.WriteLine("dump: 未找到匹配的规则。"); return 1; }
                foreach (FilterInfo f in list) DumpFilter(engine, f);
            }
            return 0;
        }

        private static void DumpFilter(WfpEngine engine, FilterInfo f)
        {
            Console.WriteLine();
            Console.WriteLine("# 规则 ID: " + f.Id + "  名称: " + (f.Name ?? "") + "  Key: {" + f.FilterKey + "}");
            Console.WriteLine("# 复制下面命令执行即可创建等价规则, 修改参数可快速生成新规则:");

            if (f.Action != Native.FWP_ACTION_BLOCK && f.Action != Native.FWP_ACTION_PERMIT)
            {
                Console.WriteLine("# 无法还原: 动作类型 0x" + f.Action.ToString("X") + " 不是 BLOCK/PERMIT, add 不支持。");
                return;
            }
            Console.Write("wfpctl add --action " + (f.Action == Native.FWP_ACTION_BLOCK ? "block" : "permit"));
            if (!string.IsNullOrEmpty(f.Name)) Console.Write(" --name " + Q(f.Name));
            if (!string.IsNullOrEmpty(f.Desc)) Console.Write(" --desc " + Q(f.Desc));

            string alias = LayerAlias.AliasOf(f.Layer);
            Console.Write(" --layer " + (alias ?? ("{" + f.Layer + "}")));
            if (f.Sublayer != WfpGuids.WfpCtlSublayer) Console.Write(" --sublayer {" + f.Sublayer + "}");

            if ((f.Flags & Native.FWPM_FILTER_FLAG_BOOTTIME) != 0) Console.Write(" --boottime");
            else if ((f.Flags & Native.FWPM_FILTER_FLAG_PERSISTENT) == 0) Console.Write(" --volatile");
            if ((f.Flags & Native.FWPM_FILTER_FLAG_DISABLED) != 0) Console.Write("  # 注: 原规则为禁用状态, add 无法保留");

            if (f.Weight != null && f.Weight.O != null && f.Weight.T == Native.FWP_UINT8)
                Console.Write(" --weight " + ((byte)(object)f.Weight.O).ToString());

            List<string> notes = new List<string>();
            HashSet<Guid> mapped = new HashSet<Guid>();
            HashSet<string> seenNotes = new HashSet<string>();
            foreach (CondInfo c in f.Conds)
            {
                string argName, argVal, note;
                if (!TryConvertToArg(c, out argName, out argVal, out note))
                {
                    if (note != null && seenNotes.Add(note)) notes.Add(note);
                    continue;
                }
                bool isAddrField = (c.FieldKey == WfpGuids.CondIpLocalAddr || c.FieldKey == WfpGuids.CondIpRemoteAddr);
                if (!isAddrField && !mapped.Add(c.FieldKey))
                {
                    string n = "原规则含多个 " + FieldName(c.FieldKey) + " 条件 (与运算), 一条命令只能还原第一个";
                    if (seenNotes.Add(n)) notes.Add(n);
                    continue;
                }
                if (isAddrField) mapped.Add(c.FieldKey);   // 地址字段允许重复 (add 支持多个)
                Console.Write(" " + argName + " " + argVal);
            }
            Console.WriteLine();
            foreach (string n in notes) Console.WriteLine("# 注: " + n);
            Console.WriteLine("# 执行后返回新规则 ID; 需管理员权限。");
        }

        // 条件 → add 参数 (参数名, 参数值). 无法还原时返回 false, note 说明原因 (null=忽略)
        private static bool TryConvertToArg(CondInfo c, out string argName, out string argVal, out string note)
        {
            argName = null; argVal = null; note = null;
            V v = c.Value;
            if (v == null || v.O == null) { note = "条件值缺失"; return false; }

            if (c.FieldKey == WfpGuids.CondIpProtocol)
            {
                if (c.MatchType != Native.FWP_MATCH_EQUAL || v.T != Native.FWP_UINT8)
                { note = "协议条件无法还原"; return false; }
                byte p = (byte)(object)v.O;
                argName = "--protocol";
                argVal = (p == 6) ? "tcp" : (p == 17) ? "udp" : (p == 1) ? "icmp" : (p == 58) ? "icmpv6" : p.ToString();
                return true;
            }
            if (c.FieldKey == WfpGuids.CondIpLocalPort || c.FieldKey == WfpGuids.CondIpRemotePort)
            {
                argName = (c.FieldKey == WfpGuids.CondIpLocalPort) ? "--lport" : "--rport";
                if (c.MatchType == Native.FWP_MATCH_EQUAL && v.T == Native.FWP_UINT16)
                { argVal = ((ushort)(object)v.O).ToString(); return true; }
                if (c.MatchType == Native.FWP_MATCH_RANGE && v.T == Native.FWP_RANGE_TYPE)
                {
                    CondRange r = (CondRange)(object)v.O;
                    if (r.Lo.T == Native.FWP_UINT16 && r.Hi.T == Native.FWP_UINT16)
                    {
                        argVal = ((ushort)(object)r.Lo.O).ToString() + "-" + ((ushort)(object)r.Hi.O).ToString();
                        return true;
                    }
                }
                note = "端口条件无法还原"; return false;
            }
            if (c.FieldKey == WfpGuids.CondIpLocalAddr || c.FieldKey == WfpGuids.CondIpRemoteAddr)
            {
                argName = (c.FieldKey == WfpGuids.CondIpLocalAddr) ? "--lip" : "--rip";
                if (c.MatchType == Native.FWP_MATCH_EQUAL && v.T == Native.FWP_V4_ADDR_MASK)
                {
                    uint[] m = (uint[])(object)v.O;
                    string ip = UintToIp(m[0]);
                    int pfx = PopCount(m[1]);
                    argVal = (pfx == 32) ? ip : (ip + "/" + pfx);
                    return true;
                }
                if (c.MatchType == Native.FWP_MATCH_EQUAL && v.T == Native.FWP_UINT32)
                { argVal = UintToIp((uint)(object)v.O); return true; }
                if (c.MatchType == Native.FWP_MATCH_EQUAL && v.T == Native.FWP_V6_ADDR_MASK)
                {
                    byte[] b = (byte[])(object)v.O;
                    byte[] ab = new byte[16];
                    Array.Copy(b, ab, 16);
                    string s = new IPAddress(ab).ToString();
                    int pfx = (b.Length > 16) ? b[16] : 128;
                    argVal = (pfx == 128) ? s : (s + "/" + pfx);
                    return true;
                }
                if (c.MatchType == Native.FWP_MATCH_RANGE && v.T == Native.FWP_RANGE_TYPE)
                {
                    CondRange r = (CondRange)(object)v.O;
                    if (r.Lo.T == Native.FWP_UINT32 && r.Hi.T == Native.FWP_UINT32)
                    {
                        uint l = (uint)(object)r.Lo.O, h = (uint)(object)r.Hi.O;
                        if (l <= h)
                        {
                            uint diff = h - l + 1;
                            if ((diff & (diff - 1)) == 0 && (l & (diff - 1)) == 0)
                            {
                                int prefix = 32; uint d = diff;
                                while (d > 1) { d >>= 1; prefix--; }
                                argVal = UintToIp(l) + "/" + prefix;
                                return true;
                            }
                            note = "地址范围 " + UintToIp(l) + " ~ " + UintToIp(h) + " 不对齐网段, add 无法精确还原";
                            return false;
                        }
                    }
                }
                note = "地址条件无法还原"; return false;
            }
            if (c.FieldKey == WfpGuids.CondAleAppId)
            {
                if (c.MatchType != Native.FWP_MATCH_EQUAL || v.T != Native.FWP_BYTE_BLOB_TYPE)
                { note = "应用条件无法还原"; return false; }
                byte[] b = (byte[])(object)v.O;
                if (b != null && b.Length > 0)
                {
                    string path = Encoding.Unicode.GetString(b).TrimEnd('\0');
                    bool ok = path.Length > 0;
                    foreach (char ch in path) if (char.IsControl(ch)) { ok = false; break; }
                    if (ok) { argName = "--app"; argVal = Q(path); return true; }
                }
                note = "应用条件无法还原为路径"; return false;
            }
            note = "未知条件 " + FieldName(c.FieldKey) + " 无法还原"; return false;
        }

        // 命令行参数值引号包裹: 含空格/引号时用双引号 (内部引号转单引号)
        private static string Q(string s)
        {
            if (s == null) return "\"\"";
            bool need = false;
            foreach (char ch in s) if (ch == ' ' || ch == '\t' || ch == '"') { need = true; break; }
            string t = s.Replace("\"", "'");
            return need ? "\"" + t + "\"" : t;
        }

        private static string FieldName(Guid g)
        {
            if (g == WfpGuids.CondIpProtocol) return "协议";
            if (g == WfpGuids.CondIpLocalAddr) return "本地地址";
            if (g == WfpGuids.CondIpRemoteAddr) return "远程地址";
            if (g == WfpGuids.CondIpLocalPort) return "本地端口";
            if (g == WfpGuids.CondIpRemotePort) return "远程端口";
            if (g == WfpGuids.CondAleAppId) return "应用程序";
            if (g == WfpGuids.CondAleUserId) return "用户";
            if (g == WfpGuids.CondIpsecQmSaId) return "IPsec SA ID";
            string nm;
            if (s_condNames.TryGetValue(g, out nm)) return nm;
            return "{" + g + "}";
        }

        // SDK fwpmu.h 内置条件字段 GUID → 中文名 (工具常用字段之外的全量补充)
        private static readonly Dictionary<Guid, string> s_condNames = new Dictionary<Guid, string>
        {
            { new Guid("f6e63dce-1f4b-4c6b-b6ef-1165e71f8ee7"), "接口MAC地址" },
            { new Guid("d999e981-7948-4c8e-b742-c84e3b678f8f"), "本地MAC地址" },
            { new Guid("408f2ed4-3a70-4b4d-92a6-415ac20e2f12"), "远程MAC地址" },
            { new Guid("fd08948d-a219-4d52-bb98-1a5540ee7b4e"), "以太网类型" },
            { new Guid("938eab21-3618-4e64-9ca5-2141ebda1ca2"), "VLAN ID" },
            { new Guid("7bc43cbf-37ba-45f1-b74a-82ff518eeb10"), "二层标志" },
            { new Guid("cc31355c-3073-4ffb-a14f-79415cb1ead1"), "本地MAC地址类型" },
            { new Guid("027fedb4-f1c1-4030-b564-ee777fd867ea"), "远程MAC地址类型" },
            { new Guid("71bc78fa-f17c-4997-a602-6abb261f351c"), "应用包ID" },
            { new Guid("7b795451-f1f6-4d05-b7cb-21779d802336"), "源MAC地址" },
            { new Guid("04ea2a93-858c-4027-b613-b43180c7859e"), "目的MAC地址" },
            { new Guid("5c1b72e4-299e-4437-a298-bc3f014b3dc2"), "源MAC地址类型" },
            { new Guid("ae052932-ef42-4e99-b129-f3b3139e34f7"), "目的MAC地址类型" },
            { new Guid("a6afef91-3df4-4730-a214-f5426aebf821"), "源端口" },
            { new Guid("ce6def45-60fb-4a7b-a304-af30a117000e"), "目的端口" },
            { new Guid("ae96897e-2e94-4bc9-b313-b27ee80e574d"), "源IP地址" },
            { new Guid("2d79133b-b390-45c6-8699-acaceaafed33"), "目的IP地址" },
            { new Guid("6ec7f6c4-376b-45d7-9e9c-d337cedcd237"), "本地地址类型" },
            { new Guid("1ec1b7c9-4eea-4f5e-b9ef-76beaaaf17ee"), "目的地址类型" },
            { new Guid("eabe448a-a711-4d64-85b7-3f76b65299c7"), "下一跳地址" },
            { new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4"), "本地接口" },
            { new Guid("618a9b6d-386b-4136-ad6e-b51587cfb1cd"), "到达接口" },
            { new Guid("89f990de-e798-4e6d-ab76-7c9558292e6f"), "到达接口类型" },
            { new Guid("511166dc-7a8c-4aa7-b533-95ab59fb0340"), "到达隧道类型" },
            { new Guid("cc088db3-1792-4a71-b0f9-037d21cd828b"), "到达接口索引" },
            { new Guid("ef8a6122-0577-45a7-9aaf-825fbeb4fb95"), "下一跳子接口索引" },
            { new Guid("93ae8f5b-7f6f-4719-98c8-14e97429ef04"), "下一跳接口" },
            { new Guid("97537c6c-d9a3-4767-a381-e942675cd920"), "下一跳接口类型" },
            { new Guid("72b1a111-987b-4720-99dd-c7c576fa2d4c"), "下一跳隧道类型" },
            { new Guid("138e6888-7ab8-4d65-9ee8-0591bcf6a494"), "下一跳接口索引" },
            { new Guid("46ea1551-2255-492b-8019-aabeee349f40"), "原始配置文件ID" },
            { new Guid("ab3033c9-c0e3-4759-937d-5758c65d4ae3"), "当前配置文件ID" },
            { new Guid("4ebf7562-9f18-4d06-9941-a7a625744d71"), "本地接口配置文件ID" },
            { new Guid("cdfe6aab-c083-4142-8679-c08f95329c61"), "到达接口配置文件ID" },
            { new Guid("d7ff9a56-cdaa-472b-84db-d23963c1d1bf"), "下一跳接口配置文件ID" },
            { new Guid("11205e8c-11ae-457a-8a44-477026dd764a"), "重新授权原因" },
            { new Guid("076dfdbe-c56c-4f72-ae8a-2cfe7e5c8286"), "原始ICMP类型" },
            { new Guid("da50d5c8-fa0d-4c89-b032-6e62136d1e96"), "物理到达接口" },
            { new Guid("f09bd5ce-5150-48be-b098-c25152fb1f92"), "物理下一跳接口" },
            { new Guid("cce68d5e-053b-43a8-9a6f-33384c28e4f6"), "接口隔离纪元" },
            { new Guid("daf8cd14-e09e-4c93-a5ae-c5c13b73ffca"), "接口类型" },
            { new Guid("77a40437-8779-4868-a261-f5a902f1c0cd"), "隧道类型" },
            { new Guid("1076b8a5-6323-4c5e-9810-e8d3fc9e6136"), "IP转发接口" },
            { new Guid("4672a468-8a0a-4202-abb4-849e92e66809"), "内嵌本地地址类型" },
            { new Guid("77ee4b39-3273-4671-b63b-ab6feb66eeb6"), "内嵌远程地址" },
            { new Guid("07784107-a29e-4c7b-9ec7-29c44afafdbc"), "内嵌协议" },
            { new Guid("bfca394d-acdb-484e-b8e6-2aff79757345"), "内嵌本地端口" },
            { new Guid("cae4d6a1-2968-40ed-a4ce-547160dda88d"), "内嵌远程端口" },
            { new Guid("632ce23b-5167-435c-86d7-e903684aa80c"), "标志" },
            { new Guid("8784c146-ca97-44d6-9fd1-19fb1840cbf7"), "方向" },
            { new Guid("667fd755-d695-434a-8af5-d3835a1259bc"), "接口索引" },
            { new Guid("0cd42473-d621-4be3-ae8c-72a348d283e1"), "子接口索引" },
            { new Guid("2311334d-c92d-45bf-9496-edf447820e2d"), "源接口索引" },
            { new Guid("055edd9d-acd2-4361-8dab-f9525d97662f"), "源子接口索引" },
            { new Guid("35cf6522-4139-45ee-a0d5-67b80949d879"), "目的接口索引" },
            { new Guid("2b7d4399-d4c7-4738-a2f5-e994b43da388"), "目的子接口索引" },
            { new Guid("0e6cd086-e1fb-4212-842f-8a9f993fb3f6"), "原始应用程序" },
            { new Guid("f63073b7-0189-4ab0-95a4-6123cbfab862"), "远程用户" },
            { new Guid("1aa47f51-7f93-4508-a271-81abb00c9cab"), "远程计算机" },
            { new Guid("1c974776-7182-46e9-afd3-b02910e30334"), "混杂模式" },
            { new Guid("b482d227-1979-4a98-8044-18bbe6237542"), "ALE重新授权原因" },
            { new Guid("46275a9d-c03f-4d77-b784-1c57f4d02753"), "ALE NAP上下文" },
            { new Guid("37a57699-5883-4963-92b8-3e704688b0ad"), "应用安全属性FQBN" },
            { new Guid("b1277b9a-b781-40fc-9671-e5f1b989f34e"), "有效名称" },
            { new Guid("37a57700-5884-4964-92b8-3e704688b0ad"), "IPsec安全域ID" },
            { new Guid("35d0ea0e-15ca-492b-900e-97fd46352cce"), "IPsec认证NAP上下文" },
            { new Guid("9bf0ee66-06c9-41b9-84da-288cb43af51f"), "远程用户令牌" },
            { new Guid("7c9c7d9f-0075-4d35-a0d1-8311c4cf6af1"), "RPC接口UUID" },
            { new Guid("eabfd9b7-1262-4a2e-adaa-5f96f6fe326d"), "RPC接口版本" },
            { new Guid("238a8a32-3199-467d-871c-272621ab3896"), "RPC接口标志" },
            { new Guid("ff2e7b4d-3112-4770-b636-4d24ae3a6af2"), "DCOM应用ID" },
            { new Guid("d024de4d-deaa-4317-9c85-e40ef6e140c3"), "镜像名称" },
            { new Guid("2717bc74-3a35-4ce7-b7ef-c838fabdec45"), "RPC协议" },
            { new Guid("daba74ab-0d67-43e7-986e-75b84f82f594"), "RPC认证类型" },
            { new Guid("e5a0aed5-59ac-46ea-be05-a5f05ecf446e"), "RPC认证级别" },
            { new Guid("0d306ef0-e974-4f74-b5c7-591b0da7d562"), "加密算法" },
            { new Guid("4772183b-ccf8-4aeb-bce1-c6c6161c8fe4"), "密钥长度" },
            { new Guid("1bd0741d-e3df-4e24-8634-762046eef6eb"), "管道" },
            { new Guid("e31180a8-bbbd-4d14-a65e-7157b06233bb"), "RPC进程UUID" },
            { new Guid("dccea0b9-0886-4360-9c6a-ab043a24fba9"), "RPC端点值" },
            { new Guid("218b814a-0a39-49b8-8e71-c20c39c7dd2e"), "RPC端点标志" },
            { new Guid("c228fc1e-403a-4478-be05-c9baa4c05ace"), "客户端令牌" },
            { new Guid("b605a225-c3b3-48c7-9833-7aefa9527546"), "RPC服务器名" },
            { new Guid("8090f645-9ad5-4e3b-9f9f-8023ca097909"), "RPC服务器端口" },
            { new Guid("40953fe2-8565-4759-8488-1771b4b4b5db"), "RPC代理认证类型" },
            { new Guid("a3ec00c7-05f4-4df7-91f2-5f60d91ff443"), "客户端证书密钥长度" },
            { new Guid("c491ad5e-f882-4283-b916-436b103ff4ad"), "客户端证书OID" },
            { new Guid("206e9996-490e-40cf-b831-b38641eb6fcb"), "网络事件类型" },
            { new Guid("9b539082-eb90-4186-a6cc-de5b63235016"), "对等名称" },
            { new Guid("f68166fd-0682-4c89-b8f5-86436c7ef9b7"), "远程ID" },
            { new Guid("eb458cd5-da7b-4ef9-8d43-7b0a840332f2"), "认证类型" },
            { new Guid("ff0f5f49-0ceb-481b-8638-1479791f3f2c"), "密钥管理类型" },
            { new Guid("feef4582-ef8f-4f7b-858b-9077d122de47"), "密钥管理模式" },
            { new Guid("ad37dee3-722f-45cc-a4e3-068048124452"), "IPsec策略Key" },
            { new Guid("f64fc6d1-f9cb-43d2-8a5f-e13bc894f265"), "IPsec快速模式" },
            { new Guid("dc04843c-79e6-4e44-a025-65b9bb0f9f94"), "vSwitch租户网络ID" },
            { new Guid("c4a414ba-437b-4de6-9946-d99c1b95b312"), "vSwitch ID" },
            { new Guid("11d48b4b-e77a-40b4-9155-392c906c2608"), "vSwitch网络类型" },
            { new Guid("db7bb42b-2dac-4cd4-a59a-e0bdce1e6834"), "NDIS端口" },
        };

        private static string MatchName(uint m)
        {
            switch (m)
            {
                case Native.FWP_MATCH_EQUAL: return "=";
                case Native.FWP_MATCH_GREATER: return ">";
                case Native.FWP_MATCH_LESS: return "<";
                case Native.FWP_MATCH_GREATER_OR_EQUAL: return ">=";
                case Native.FWP_MATCH_LESS_OR_EQUAL: return "<=";
                case Native.FWP_MATCH_RANGE: return "在范围内";
                case Native.FWP_MATCH_FLAGS_ALL_SET: return "标志全为1";
                case Native.FWP_MATCH_FLAGS_ANY_SET: return "标志任一为1";
                case Native.FWP_MATCH_FLAGS_NONE_SET: return "标志全为0";
                case Native.FWP_MATCH_EQUAL_CASE_INSENSITIVE: return "等于(忽略大小写)";
                case Native.FWP_MATCH_NOT_EQUAL: return "!=";
                case Native.FWP_MATCH_PREFIX: return "前缀";
                default: return "0x" + m.ToString("X");
            }
        }

        private static string TypeName(V v)
        {
            if (v == null) return "";
            switch (v.T)
            {
                case Native.FWP_UINT8: return "UINT8";
                case Native.FWP_UINT16: return "UINT16";
                case Native.FWP_UINT32: return "UINT32";
                case Native.FWP_INT8: return "INT8";
                case Native.FWP_INT16: return "INT16";
                case Native.FWP_INT32: return "INT32";
                case Native.FWP_UINT64:
                case Native.FWP_INT64: return "UINT64";
                case Native.FWP_FLOAT: return "FLOAT";
                case Native.FWP_DOUBLE: return "DOUBLE";
                case Native.FWP_BYTE_ARRAY16_TYPE: return "ARRAY16";
                case Native.FWP_BYTE_BLOB_TYPE: return "BLOB";
                case Native.FWP_SECURITY_DESCRIPTOR_TYPE: return "SD";
                case Native.FWP_SID: return "SID";
                case Native.FWP_UNICODE_STRING_TYPE: return "UNISTR";
                case Native.FWP_V4_ADDR_MASK: return "V4MASK";
                case Native.FWP_V6_ADDR_MASK: return "V6MASK";
                case Native.FWP_RANGE_TYPE: return "RANGE";
                case Native.FWP_EMPTY: return "EMPTY";
                default: return "0x" + v.T.ToString("X");
            }
        }

        private static string GetProviderName(WfpEngine engine, Guid key)
        {
            try
            {
                IntPtr p;
                int hr = Native.FwpmProviderGetByKey0(engine.Handle, ref key, out p);
                if (hr != 0 || p == IntPtr.Zero) return null;
                try
                {
                    // FWPM_PROVIDER0: GUID(16) + FWPM_DISPLAY_DATA0(name_ptr@16, desc_ptr@24)
                    IntPtr namePtr = Marshal.ReadIntPtr(p, 16);
                    if (namePtr != IntPtr.Zero) return Marshal.PtrToStringUni(namePtr);
                    return null;
                }
                finally { Native.FwpmFreeMemory0(ref p); }
            }
            catch { return null; }
        }

        // 基于已托管化的 V 结构渲染条件值 (无指针访问, 安全)
        private static string FormatCondValue(CondInfo c)
        {
            V v = c.Value;
            // 配置文件 ID 字段解码: 1=域 2=专用 4=公用
            if (IsProfileIdField(c.FieldKey) && v != null && v.T == Native.FWP_UINT32)
                return ((uint)(object)v.O).ToString() + " (" + ProfileName((uint)(object)v.O) + ")";
            bool isPort = (c.FieldKey == WfpGuids.CondIpLocalPort || c.FieldKey == WfpGuids.CondIpRemotePort);
            bool isAddr = (c.FieldKey == WfpGuids.CondIpLocalAddr || c.FieldKey == WfpGuids.CondIpRemoteAddr);
            return RenderValue(v, isPort, isAddr);
        }

        private static bool IsProfileIdField(Guid g)
        {
            return g == new Guid("46ea1551-2255-492b-8019-aabeee349f40") ||
                   g == new Guid("ab3033c9-c0e3-4759-937d-5758c65d4ae3") ||
                   g == new Guid("4ebf7562-9f18-4d06-9941-a7a625744d71") ||
                   g == new Guid("cdfe6aab-c083-4142-8679-c08f95329c61") ||
                   g == new Guid("d7ff9a56-cdaa-472b-84db-d23963c1d1bf");
        }

        private static string ProfileName(uint p)
        {
            string s = "";
            if ((p & 1) != 0) s += "域";
            if ((p & 2) != 0) s += (s.Length > 0 ? ", " : "") + "专用";
            if ((p & 4) != 0) s += (s.Length > 0 ? ", " : "") + "公用";
            return (s.Length > 0) ? s : "未知";
        }

        private static string RenderValue(V v, bool isPort, bool isAddr)
        {
            if (v == null) return "<无条件>";
            try
            {
                switch (v.T)
                {
                    case Native.FWP_UINT8:
                        return ProtoOrNum((byte)(object)v.O);
                    case Native.FWP_UINT16:
                        return ((ushort)(object)v.O).ToString();
                    case Native.FWP_UINT32:
                        {
                            uint u = (uint)(object)v.O;
                            return isAddr ? UintToIp(u) : u.ToString();
                        }
                    case Native.FWP_INT8:
                        return ((sbyte)(object)v.O).ToString();
                    case Native.FWP_INT16:
                        return ((short)(object)v.O).ToString();
                    case Native.FWP_INT32:
                        return ((int)(object)v.O).ToString();
                    case Native.FWP_UINT64:
                    case Native.FWP_INT64:
                        return ((long)(object)v.O).ToString();
                    case Native.FWP_FLOAT:
                        return ((float)(object)v.O).ToString(CultureInfo.InvariantCulture);
                    case Native.FWP_DOUBLE:
                        return ((double)(object)v.O).ToString(CultureInfo.InvariantCulture);
                    case Native.FWP_BYTE_ARRAY16_TYPE:
                        return new IPAddress((byte[])(object)v.O).ToString();
                    case Native.FWP_BYTE_BLOB_TYPE:
                    case Native.FWP_SECURITY_DESCRIPTOR_TYPE:
                        {
                            byte[] b = (byte[])(object)v.O;
                            if (b == null || b.Length == 0) return "<空>";
                            if (v.T == Native.FWP_SECURITY_DESCRIPTOR_TYPE)
                            {
                                // 将 SD 字节转换为 SDDL 字符串
                                IntPtr p = Marshal.AllocHGlobal(b.Length);
                                try
                                {
                                    Marshal.Copy(b, 0, p, b.Length);
                                    IntPtr sddl; uint len;
                                    if (Native.ConvertSecurityDescriptorToStringSecurityDescriptor(p, 1, 7, out sddl, out len) && sddl != IntPtr.Zero)
                                    {
                                        string s = Marshal.PtrToStringUni(sddl);
                                        Native.LocalFree(sddl);
                                        return s;
                                    }
                                }
                                finally { Marshal.FreeHGlobal(p); }
                                return "<安全描述符 " + b.Length + " 字节>";
                            }
                            // ALE_APP_ID 等为 UTF-16 字节流
                            if ((b.Length & 1) == 0)
                            {
                                string s = Encoding.Unicode.GetString(b);
                                bool printable = true;
                                for (int i = 0; i < s.Length; i++)
                                    if (char.IsControl(s[i]) && s[i] != '\0') { printable = false; break; }
                                if (printable) return s.TrimEnd('\0');
                            }
                            return "<数据 " + b.Length + " 字节>";
                        }
                    case Native.FWP_SID:
                        return (string)(object)v.O ?? "<SID>";
                    case Native.FWP_UNICODE_STRING_TYPE:
                        return (string)(object)v.O ?? "";
                    case Native.FWP_V4_ADDR_MASK:
                        {
                            uint[] m = (uint[])(object)v.O;
                            uint a = m[0];
                            // addr 为网络字节序数值: 0xAABBCCDD 即 A.B.C.D
                            string addr = string.Format("{0}.{1}.{2}.{3}",
                                (a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
                            int prefix = PopCount(m[1]);
                            return (prefix == 32) ? addr : (addr + "/" + prefix);
                        }
                    case Native.FWP_V6_ADDR_MASK:
                        {
                            byte[] b = (byte[])(object)v.O;
                            byte[] addr = new byte[16];
                            Array.Copy(b, addr, 16);
                            int prefix = (b.Length > 16) ? b[16] : 128;
                            string s = new IPAddress(addr).ToString();
                            return (prefix == 128) ? s : (s + "/" + prefix);
                        }
                    case Native.FWP_RANGE_TYPE:
                        {
                            CondRange r = (CondRange)(object)v.O;
                            return RenderRange(r.Lo, r.Hi, isPort, isAddr);
                        }
                    case Native.FWP_EMPTY:
                        return "<无条件>";
                    default:
                        if (v.O == null) return "(类型 " + v.T + ")";
                        return v.O.ToString();
                }
            }
            catch (Exception ex)
            {
                return "<解析失败: " + ex.Message + ">";
            }
        }

        private static string ProtoOrNum(byte b)
        {
            switch (b)
            {
                case 1: return "ICMP (1)";
                case 6: return "TCP (6)";
                case 17: return "UDP (17)";
                case 47: return "GRE (47)";
                case 58: return "ICMPv6 (58)";
                default: return b.ToString();
            }
        }

        private static int PopCount(uint x)
        {
            int n = 0;
            while (x != 0) { n += (int)(x & 1); x >>= 1; }
            return n;
        }

        // 网络字节序数值 (0xAABBCCDD) → 点分 IP
        private static string UintToIp(uint a)
        {
            return string.Format("{0}.{1}.{2}.{3}",
                (a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
        }

        // 渲染范围值: 地址范围对齐单个 CIDR 块时显示 "ip/prefix", 否则 "ip1 ~ ip2"
        private static string RenderRange(V lo, V hi, bool isPort, bool isAddr)
        {
            if (isAddr && !isPort && lo.T == Native.FWP_UINT32 && hi.T == Native.FWP_UINT32)
            {
                uint l = (uint)(object)lo.O, h = (uint)(object)hi.O;
                if (l <= h)
                {
                    uint diff = h - l + 1;
                    if ((diff & (diff - 1)) == 0 && (l & (diff - 1)) == 0)
                    {
                        int prefix = 32;
                        uint d = diff;
                        while (d > 1) { d >>= 1; prefix--; }
                        return UintToIp(l) + "/" + prefix;
                    }
                    return UintToIp(l) + " ~ " + UintToIp(h);
                }
            }
            return RenderValue(lo, isPort, isAddr) + " ~ " + RenderValue(hi, isPort, isAddr);
        }

        // ================== del ==================
        private static int CmdDel(string[] a)
        {
            if (a.Length != 1 && a.Length != 2)
            { Console.Error.WriteLine("用法: wfpctl del <规则ID>   或   wfpctl del --name <规则名称>"); return 1; }

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();

                if (a[0] == "--name")
                {
                    if (a.Length != 2) { Console.Error.WriteLine("del: --name 后需要规则名称。"); return 1; }
                    List<FilterInfo> filters = engine.EnumFilters();
                    List<ulong> matched = new List<ulong>();
                    foreach (FilterInfo f in filters)
                    {
                        if (f.Name == a[1]) matched.Add(f.Id);
                    }
                    if (matched.Count == 0)
                    { Console.Error.WriteLine("del: 没有找到名称为 \"" + a[1] + "\" 的规则。"); return 1; }

                    int fail = 0;
                    foreach (ulong id in matched)
                    {
                        int hr = Native.FwpmFilterDeleteById0(engine.Handle, id);
                        if (hr != 0)
                        {
                            fail++;
                            Console.Error.WriteLine(string.Format(
                                "del: 删除 ID {0} 失败 (0x{1:X8})", id, (uint)hr));
                        }
                        else Console.WriteLine("已删除规则 ID = " + id);
                    }
                    return fail == 0 ? 0 : 1;
                }
                else
                {
                    ulong id;
                    if (!ulong.TryParse(a[0], out id))
                    { Console.Error.WriteLine("del: 规则 ID 必须是数字。"); return 1; }
                    int hr = Native.FwpmFilterDeleteById0(engine.Handle, id);
                    if (hr != 0)
                    {
                        if ((uint)hr == 0x80320003)
                            Console.Error.WriteLine("del: 未找到 ID 为 " + id + " 的规则。");
                        else
                            throw new WfpException(hr, string.Format(
                                "删除规则 {0} 失败 (FwpmFilterDeleteById0)。", id));
                        return 1;
                    }
                    Console.WriteLine("已删除规则 ID = " + id);
                    return 0;
                }
            }
        }

        // ================== layers ==================
        private static int CmdLayers()
        {
            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                List<LayerInfo> layers = engine.EnumLayers();

                Console.WriteLine();
                Console.WriteLine("本机 WFP 过滤层 (共 " + layers.Count + " 个):");
                Console.WriteLine(new string('-', 78));
                foreach (LayerInfo l in layers)
                {
                    string alias = LayerAlias.AliasOf(l.Key);
                    string mark = alias != null ? "  <-- 可用别名: " + alias : "";
                    Console.WriteLine(Pad(l.Name, 34) + "{" + l.Key + "}" + mark);
                    if (l.Desc != null && l.Desc.Length > 0)
                        Console.WriteLine("    " + l.Desc);
                }
            }
            return 0;
        }

        // ================== sublayers ==================
        private static int CmdSubLayers()
        {
            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                List<SubLayerInfo> subs = engine.EnumSubLayers();

                Console.WriteLine();
                Console.WriteLine("本机 WFP 子层 (共 " + subs.Count + " 个):");
                Console.WriteLine(new string('-', 78));
                foreach (SubLayerInfo s in subs)
                {
                    string mark = (s.Key == WfpGuids.WfpCtlSublayer) ? "   [本工具默认子层]" : "";
                    Console.WriteLine("权重 " + s.Weight.ToString("X4") + "  " +
                        Pad(s.Name, 30) + "{" + s.Key + "}" + mark);
                }
            }
            return 0;
        }

        private static int CmdSubLayerAdd(string[] a)
        {
            if (a.Length != 2 && a.Length != 3)
            { Console.Error.WriteLine("用法: wfpctl sublayer-add <GUID|default> <名称> [权重0-65535]"); return 1; }

            Guid key;
            if (a[0] == "default") key = WfpGuids.WfpCtlSublayer;
            else
            {
                key = LayerAlias.Resolve(a[0]);
                if (key == Guid.Empty) { Console.Error.WriteLine("sublayer-add: 无效的 GUID。"); return 1; }
            }
            ushort weight = 0x100;
            if (a.Length == 3)
            {
                int w;
                if (!int.TryParse(a[2], out w) || w < 0 || w > 65535)
                { Console.Error.WriteLine("sublayer-add: 权重须为 0-65535。"); return 1; }
                weight = (ushort)w;
            }

            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                int hr = engine.EnsureSubLayer(key, a[1], weight);
                if (hr != 0) throw new WfpException(hr, "添加子层失败。");
                Console.WriteLine("子层已就绪: {" + key + "} 名称 = " + a[1]);
                return 0;
            }
        }

        private static int CmdSubLayerDel(string[] a)
        {
            if (a.Length != 1)
            { Console.Error.WriteLine("用法: wfpctl sublayer-del <GUID|default>"); return 1; }
            Guid key;
            if (a[0] == "default") key = WfpGuids.WfpCtlSublayer;
            else
            {
                key = LayerAlias.Resolve(a[0]);
                if (key == Guid.Empty) { Console.Error.WriteLine("sublayer-del: 无效的 GUID。"); return 1; }
            }
            using (WfpEngine engine = new WfpEngine())
            {
                engine.Open();
                int hr = Native.FwpmSubLayerDeleteByKey0(engine.Handle, ref key);
                if (hr != 0)
                {
                    if ((uint)hr == 0x80320007)
                        Console.Error.WriteLine("sublayer-del: 未找到该子层。");
                    else if ((uint)hr == 0x8032000A)
                        Console.Error.WriteLine("sublayer-del: 该子层下仍有过滤规则, 请先删除其规则。");
                    else
                        throw new WfpException(hr, "删除子层失败。");
                    return 1;
                }
                Console.WriteLine("已删除子层: {" + key + "}");
                return 0;
            }
        }

        // ================== 工具函数 ==================
        private static string Pad(string s, int width)
        {
            if (s == null) s = "<无名>";
            if (s.Length > width) s = s.Substring(0, width - 1) + "…";
            return s.PadRight(width);
        }

        // ================== 帮助 ==================
        private static void Usage()
        {
            Console.WriteLine();
            Console.WriteLine("wfpctl —— Windows 过滤平台 (WFP) 过滤规则管理工具  v1.8");
            Console.WriteLine();
            Console.WriteLine("用法: wfpctl <命令> [选项]");
            Console.WriteLine();
            Console.WriteLine("命令:");
            Console.WriteLine("  add          添加过滤规则");
            Console.WriteLine("  del          删除过滤规则 (按 ID 或 --name 按名称)");
            Console.WriteLine("  update       修改规则: update <ID> [参数], 未指定的保持原值");
            Console.WriteLine("  list         列出过滤规则 (--all 看系统全部, 默认只看本工具建的)");
            Console.WriteLine("  show         查看规则详情");
            Console.WriteLine("  dump         导出规则为 add 命令: dump <ID> 或 dump --name <关键字>");
            Console.WriteLine("  layers       列出本机所有 WFP 过滤层");
            Console.WriteLine("  sublayers    列出所有子层");
            Console.WriteLine("  sublayer-add 添加子层");
            Console.WriteLine("  sublayer-del 删除子层");
            Console.WriteLine("  help         显示本帮助");
            Console.WriteLine();
            Console.WriteLine("add 选项:");
            Console.WriteLine("  --name <名称>            规则显示名 (默认 \"wfpctl rule\")");
            Console.WriteLine("  --desc <描述>            规则描述");
            Console.WriteLine("  --action <block|permit>  匹配后动作, 默认 permit (放行); 阻断需显式 --action block");
            Console.WriteLine("  --layer <层>             过滤层, 别名或 GUID, 默认 connect-v4");
            Console.Write(LayerAlias.ListForHelp());
            Console.WriteLine("  --sublayer <GUID>        所属子层, 默认使用本工具内置子层");
            Console.WriteLine("  --protocol <p>           协议: tcp|udp|icmp|icmpv6|数字(0-255)");
            Console.WriteLine("  --lport <端口>           本地端口: 80 / 1000-2000 / 80,443 (多值会拆成多条规则)");
            Console.WriteLine("  --rport <端口>           远程端口, 同上");
            Console.WriteLine("  --lip <IP[/掩码]>        本地地址: 10.0.0.5 / 10.0.0.0/8 / 10.0.0.0/255.0.0.0 / IPv6");
            Console.WriteLine("  --rip <IP[/掩码]>        远程地址, 同上");
            Console.WriteLine("  --app <程序路径>         按应用过滤, 文件必须存在, 如 C:\\path\\app.exe");
            Console.WriteLine("  --weight <0-15>          过滤器权重, 同子层内高的先评估 (缺省自动分配);");
            Console.WriteLine("                            例如白名单场景: PERMIT 例外用 15, 整体 BLOCK 用 0");
            Console.WriteLine("  --boottime               创建为启动时间规则 (BFE 未启动时即生效)");
            Console.WriteLine("  --volatile               规则不持久化, 程序退出后即消失 (默认持久)");
            Console.WriteLine();
            Console.WriteLine("list 选项:");
            Console.WriteLine("  --all                    列出系统全部过滤规则");
            Console.WriteLine("  --name <关键字>          按名称/描述关键字筛选 (不区分大小写, 可与 --all 组合)");
            Console.WriteLine("  --action <block|permit>  按动作筛选");
            Console.WriteLine("  --layer <层>             按层筛选");
            Console.WriteLine("  --sublayer <GUID|名称|default> 按子层筛选 (名称支持模糊匹配, 可命中多个子层)");
            Console.WriteLine();
            Console.WriteLine("update 选项 (在 add 参数基础上, 未指定的参数保持原值):");
            Console.WriteLine("  update <ID> --rport 443        修改远程端口 (单值或单范围)");
            Console.WriteLine("  update <ID> --action block     改为阻断");
            Console.WriteLine("  update <ID> --rip any          清除远程地址条件 (any 即清除)");
            Console.WriteLine("  update <ID> --weight auto      恢复自动权重");
            Console.WriteLine("  修改为事务内“删旧+建新”, 规则 ID 会变化, 失败自动回滚。");
            Console.WriteLine();
            Console.WriteLine("示例:");
            Console.WriteLine("  wfpctl add --name \"禁出站80端口\" --action block --protocol tcp --rport 80");
            Console.WriteLine("  wfpctl add --name \"禁访问某网段\" --action block --rip 203.0.113.0/24");
            Console.WriteLine("  wfpctl add --name \"禁程序联网\" --action block --app \"C:\\Program Files\\test.exe\"");
            Console.WriteLine("  wfpctl add --name \"禁入站3389\" --action block --layer accept-v4 --protocol tcp --rport 3389");
            Console.WriteLine("  wfpctl list --name 80端口");
            Console.WriteLine("  wfpctl list --all --name mssec");
            Console.WriteLine("  wfpctl show 12345");
            Console.WriteLine("  wfpctl dump 12345");
            Console.WriteLine("  wfpctl dump --name 80端口");
            Console.WriteLine("  wfpctl update 12345 --rport 443");
            Console.WriteLine("  wfpctl del 12345");
            Console.WriteLine("  wfpctl del --name \"禁出站80端口\"");
            Console.WriteLine();
            Console.WriteLine("说明:");
            Console.WriteLine("  * 增删规则需要以管理员身份运行本工具 (依赖系统 BFE 服务)。");
            Console.WriteLine("  * 规则默认持久化, 重启系统后仍然生效; 退出程序不影响规则。");
            Console.WriteLine("  * 本工具规则挂在专属子层下, 删除时绝不影响系统自带规则。");
            Console.WriteLine("  * 层别名 connect/accept 用于按连接授权 (推荐), out/in 用于按每个数据包过滤。");
            Console.WriteLine();
        }
    }
}
