using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Service;

public sealed class DriverPackageInventoryProvider
{
    private const int MaximumPackages = 1024;
    private const int MaximumTextLength = 1024;

    public DriverPackageInventorySnapshot Capture()
    {
        var warnings = new List<string>();
        var packages = new List<DriverPackageEntry>();

        // Enumerate all driver packages from the Driver Store using SetupAPI
        var hDevInfo = SetupDiGetClassDevs(IntPtr.Zero, null, IntPtr.Zero, DiGetClassFlags.DIGCF_ALLCLASSES);
        if (hDevInfo == InvalidHandleValue)
        {
            warnings.Add("Failed to open device information set for driver store enumeration.");
            return Empty(warnings);
        }

        try
        {
            var deviceInfoData = new SpDevInfoData { CbSize = Marshal.SizeOf<SpDevInfoData>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, ref deviceInfoData); i++)
            {
                // Get driver info detail for each device
                var driverInfoData = new SpDrvInfoData { CbSize = Marshal.SizeOf<SpDrvInfoData>() };
                for (uint j = 0; SetupDiEnumDriverInfo(hDevInfo, ref deviceInfoData, EnumDriverType.SPDIT_COMPATDRIVER, j, ref driverInfoData); j++)
                {
                    var detailData = new SpDrvInfoDetailData
                    {
                        CbSize = Marshal.SizeOf<SpDrvInfoDetailData>()
                    };

                    if (SetupDiGetDriverInfoDetail(hDevInfo, ref deviceInfoData, ref driverInfoData, ref detailData, MaximumTextLength, out _))
                    {
                        // Verify signature
                        var (isSigned, signerName, signatureStatus) = VerifyDriverSignature(detailData.InfFileName);

                        packages.Add(new DriverPackageEntry(
                            InfFile: Bound(detailData.InfFileName),
                            OriginalInfFile: Bound(detailData.OriginalInfFileName),
                            DriverClass: Bound(detailData.ClassName),
                            ProviderName: Bound(detailData.ProviderName),
                            DriverVersion: Bound(detailData.DriverVersion),
                            Date: Bound(detailData.DriverDateStr),
                            HardwareId: Bound(GetHardwareId(hDevInfo, ref deviceInfoData)),
                            IsSigned: isSigned,
                            SignerName: signerName,
                            SignatureStatus: signatureStatus
                        ));

                        if (packages.Count >= MaximumPackages) break;
                    }
                }
                if (packages.Count >= MaximumPackages) break;
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }

        if (packages.Count == 0)
        {
            warnings.Add("No driver packages found in the Driver Store.");
        }

        return new DriverPackageInventorySnapshot(
            1,
            DateTimeOffset.UtcNow,
            packages.Count,
            packages,
            warnings);
    }

    private static DriverPackageInventorySnapshot Empty(IReadOnlyList<string> warnings) =>
        new(1, DateTimeOffset.UtcNow, 0, [], warnings);

    private static string GetHardwareId(IntPtr hDevInfo, ref SpDevInfoData deviceInfoData)
    {
        var propertyRegDataType = 0;
        var requiredSize = 0;
        SetupDiGetDeviceRegistryProperty(
            IntPtr.Zero,
            ref deviceInfoData,
            DeviceProperty.SPDRP_HARDWAREID,
            out propertyRegDataType,
            IntPtr.Zero,
            0,
            out requiredSize);

        if (requiredSize > 0)
        {
            var buffer = Marshal.AllocHGlobal(requiredSize);
            try
            {
                if (SetupDiGetDeviceRegistryProperty(
                    IntPtr.Zero,
                    ref deviceInfoData,
                    DeviceProperty.SPDRP_HARDWAREID,
                    out propertyRegDataType,
                    buffer,
                    requiredSize,
                    out _))
                {
                    return Marshal.PtrToStringUni(buffer) ?? string.Empty;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return "";
    }

    private static (bool IsSigned, string? SignerName, string? SignatureStatus) VerifyDriverSignature(string infFile)
    {
        if (string.IsNullOrWhiteSpace(infFile) || !File.Exists(infFile))
            return (false, null, "File not found");

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = infFile,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var trustData = new WINTRUST_DATA
        {
            cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
            pPolicyCallbackData = IntPtr.Zero,
            pSIPClientData = IntPtr.Zero,
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>()),
            dwStateAction = WTD_STATEACTION_VERIFY,
            hWVTStateData = IntPtr.Zero,
            pwszURLReference = IntPtr.Zero,
            dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_CHAIN,
            dwUIContext = 0,
            pSignatureSettings = IntPtr.Zero
        };

        try
        {
            Marshal.StructureToPtr(fileInfo, trustData.pFile, false);

            var guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var result = WinVerifyTrust(IntPtr.Zero, ref guidAction, ref trustData);

            bool isSigned = result == 0;
            string? signerName = null;
            string status = result == 0 ? "Valid signature" : $"Verification failed: 0x{result:X}";

            if (isSigned)
            {
                // Extract signer name from certificate
                signerName = ExtractSignerName(infFile);
            }

            return (isSigned, signerName, status);
        }
        catch (Exception ex)
        {
            return (false, null, $"Verification error: {ex.Message}");
        }
        finally
        {
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref guidAction, ref trustData);
            if (trustData.pFile != IntPtr.Zero)
                Marshal.FreeHGlobal(trustData.pFile);
        }
    }

    private static string? ExtractSignerName(string filePath)
    {
        try
        {
            // DN-016: replace with the signer from WinVerifyTrust provider data once catalog-based verification lands.
#pragma warning disable SYSLIB0057
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            return cert.Subject;
        }
        catch
        {
            return null;
        }
    }

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x00000100;
    private const uint WTD_REVOCATION_CHECK_CHAIN = 0x00000040;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static Guid guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public int cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public int cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    private static string Bound(string value) =>
        value.Length <= 1024 ? value : value[..1024];

    #region SetupAPI P/Invoke

    private const int DIGCF_ALLCLASSES = 0x00000004;
    private const int DIGCF_PRESENT = 0x00000002;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_NO_MORE_ITEMS = 259;
    private const int MAX_PATH = 260;
    private const int LINE_LEN = 256;

    [Flags]
    private enum DiGetClassFlags : uint
    {
        DIGCF_DEFAULT = 0x00000001,
        DIGCF_PRESENT = 0x00000002,
        DIGCF_ALLCLASSES = 0x00000004,
        DIGCF_PROFILE = 0x00000008,
        DIGCF_DEVICEINTERFACE = 0x00000010,
    }

    private enum EnumDriverType : uint
    {
        SPDIT_COMPATDRIVER = 0x00000000,
        SPDIT_CLASSDRIVER = 0x00000001,
    }

    private enum DeviceProperty : uint
    {
        SPDRP_DEVICEDESC = 0x00000000,
        SPDRP_HARDWAREID = 0x00000001,
        SPDRP_COMPATIBLEIDS = 0x00000002,
        SPDRP_CLASS = 0x00000007,
        SPDRP_CLASSGUID = 0x00000008,
        SPDRP_DRIVER = 0x00000009,
        SPDRP_MFG = 0x0000000B,
        SPDRP_FRIENDLYNAME = 0x0000000C,
        SPDRP_LOCATION_INFORMATION = 0x0000000D,
        SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E,
        SPDRP_CAPABILITIES = 0x0000000F,
        SPDRP_UI_NUMBER = 0x00000010,
        SPDRP_UPPERFILTERS = 0x00000011,
        SPDRP_LOWERFILTERS = 0x00000012,
        SPDRP_BUSTYPEGUID = 0x00000013,
        SPDRP_LEGACYBUSTYPE = 0x00000014,
        SPDRP_BUSNUMBER = 0x00000015,
        SPDRP_ENUMERATOR_NAME = 0x00000016,
        SPDRP_SECURITY = 0x00000017,
        SPDRP_SECURITY_SDS = 0x00000018,
        SPDRP_DEVTYPE = 0x00000019,
        SPDRP_EXCLUSIVE = 0x0000001A,
        SPDRP_CHARACTERISTICS = 0x0000001B,
        SPDRP_ADDRESS = 0x0000001C,
        SPDRP_UI_NUMBER_DESC_FORMAT = 0x0000001D,
        SPDRP_MAXIMUM_PROPERTY = 0x0000001E,
    }

    private const int InvalidHandleValue = -1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SpDevInfoData
    {
        public int CbSize;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SpDrvInfoData
    {
        public int CbSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string Description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string MfgName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string ProviderName;
        public FILETIME DriverDate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string DriverVersion;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SpDrvInfoDetailData
    {
        public int CbSize;
        public FILETIME DriverDate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string DriverVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string DriverVersionMajor;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string DriverVersionMinor;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string DriverVersionBuild;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = LINE_LEN)]
        public string DriverVersionPrivate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string InfFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string OriginalInfFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string ClassName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string ClassGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string CompatIds;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string DriverDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string HardwareId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string ProviderName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string MfgName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string DriverDateStr;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string DriverVersionStr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(
        IntPtr classGuid,
        string? enumerator,
        IntPtr hwndParent,
        DiGetClassFlags flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiEnumDeviceInfo(
        IntPtr deviceInfoSet,
        uint memberIndex,
        ref SpDevInfoData deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiEnumDriverInfo(
        IntPtr deviceInfoSet,
        ref SpDevInfoData deviceInfoData,
        EnumDriverType driverType,
        uint memberIndex,
        ref SpDrvInfoData driverInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDriverInfoDetail(
        IntPtr deviceInfoSet,
        ref SpDevInfoData deviceInfoData,
        ref SpDrvInfoData driverInfoData,
        ref SpDrvInfoDetailData driverInfoDetailData,
        int driverInfoDetailDataSize,
        out int requiredSize);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDeviceRegistryProperty(
        IntPtr deviceInfoSet,
        ref SpDevInfoData deviceInfoData,
        DeviceProperty property,
        out int propertyRegDataType,
        IntPtr propertyBuffer,
        int propertyBufferSize,
        out int requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    #endregion
}