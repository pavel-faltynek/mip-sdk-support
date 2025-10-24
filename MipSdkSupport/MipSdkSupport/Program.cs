using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;
using Microsoft.InformationProtection.Protection;
using OpenMcdf;
using LogLevel = Microsoft.InformationProtection.LogLevel;

namespace MipSdkSupport;


internal static class Inputs
{
    public static string AppId             => GetProperty("MIP_APP_ID");
    public static string AppName           => GetProperty("MIP_APP_NAME");
    public static string AppVersion        => GetProperty("MIP_APP_VERSION", "1.0");
    public static string UserId            => GetProperty("MIP_USER_ID");
    public static string Locale            => GetProperty("MIP_LOCALE", "en-US");
    public static string LocalStoragePath  => GetProperty("MIP_LOCAL_STORAGE_PATH");
    public static byte[] HackDecryptionKey => Convert.FromBase64String(GetProperty("MIP_HACK_DECRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));

    private static string GetProperty(string name, string defValue = "") => Environment.GetEnvironmentVariable(name) ?? defValue;
}


internal class Program
{
    private const int AesBlockSize   = 16;
    private const int SuperblockSize = 4096;

    private static async Task Main(string[] args)
    {
        if (args.Length < 1) Environment.Exit(-1); // Expecting rpmsg file path as an argument

        var rpmsgFilePath = args[0];
        if (!File.Exists(rpmsgFilePath)) Environment.Exit(-2); // Expecting the file exists

        await using var rawRpmsgStream = File.OpenRead(rpmsgFilePath); // Used for both manual and handlers manipulation

        /*
         * ================================================== Inflate the rpmsg (manual read) ==================================================
         */
        Stream rpmsgStream;
        await using (var block = ReadCompressedBlock(rawRpmsgStream))
        {
            rpmsgStream = await DecompressAsync(block, true);
        }

        /*
         * ================================================== Dump intermediate data: Inflated rpmsg CFB (manual read) ==================================================
         */
        rpmsgStream.Position = 0;
        await using (var file = File.Open("01.RpmsgInflated", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await rpmsgStream.CopyToAsync(file);
        }

        /*
         * ================================================== Locate (first) *DRMContent root stream (manual read) ==================================================
         */
        rpmsgStream.Position = 0;
        using var rpmsg = RootStorage.Open(rpmsgStream);
        var drmEntries = rpmsg.EnumerateEntries().Where(e => e.Name.EndsWith("DRMContent")).ToList();
        if (drmEntries.Count < 1) Environment.Exit(-3); // Expecting at least one *DRMContent root entry
        var drmEntry = drmEntries[0];

        /*
         * ================================================== Read the Length and Contents fields (manual read) ==================================================
         */
        long cleartextLength;
        using var contents = new MemoryStream();
        await using (var drmContentStream = rpmsg.OpenStream(drmEntry.Name))
        {
            cleartextLength = ReadContentsLength(drmContentStream);
            await drmContentStream.CopyToAsync(contents);
        }

        /*
         * ================================================== Dump intermediate data: DRMContent.Contents - encrypted (manual read) ==================================================
         */
        contents.Position = 0;
        await using (var file = File.Open("02.ContentsEncrypted", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await contents.CopyToAsync(file);
        }

        /*
         * ================================================== HACK: Decrypt manually using known key extracted from MIP cache (manual read) ==================================================
         */
        contents.Position = 0;
        await using var cleartextStream = await HackDecryptUsingKnownKeyAsync(contents, Inputs.HackDecryptionKey, cleartextLength, CancellationToken.None);

        /*
         * ================================================== Dump final data: DRMContent.Contents (cleartext), represents the protected message CFB (manual read) ==================================================
         */
        cleartextStream.Position = 0;
        await using (var file = File.Open("03.ContentsDecryptedManually", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await cleartextStream.CopyToAsync(file, CancellationToken.None);
        }

        /*
         * ================================================== Initialize MIP: General (handlers read) ==================================================
         */
        var appInfo         = BuildAppInfo(Inputs.AppId, Inputs.AppName, Inputs.AppVersion);
        var authDelegate    = new AuthDelegate(appInfo);
        var consentDelegate = new ConsentDelegate();

        using var mipContext = BuildMipContext(appInfo, Inputs.LocalStoragePath);

        var rpmsgFileName = Path.GetFileName(rpmsgFilePath);

        /*
         * ================================================== Initialize MIP: File (handlers read)==================================================
         */
        rawRpmsgStream.Position = 0;
        using var fileProfile = await BuildFileProfileAsync(mipContext, CacheStorageType.OnDisk, consentDelegate);
        using var fileEngine  = await BuildFileEngineAsync(fileProfile, Inputs.UserId, authDelegate, Inputs.Locale);
        using var fileHandler = await fileEngine.CreateFileHandlerAsync(rawRpmsgStream, rpmsgFileName, true);

#if false
        /*
         * ================================================== Dump converted data: RPMSG content as msg file, with corrupted header in root properties stream (handlers read) ==================================================
         */
        var msgFileName = await fileHandler.GetDecryptedTemporaryFileAsync();
        await using (var msgFile = File.Open(msgFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            await using var file = File.Open("04.GetDecryptedTemporaryFile", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);
            await msgFile.CopyToAsync(file);
        }
#endif

        /*
         * ================================================== Dump converted data: RPMSG content as msg file, with corrupted header in root properties stream (handlers read) ==================================================
         */
        await using (var msgStream = await fileHandler.GetDecryptedTemporaryStreamAsync())
        {
            msgStream.Position = 0;
            await using var file = File.Open("05.GetDecryptedTemporaryStream", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);
            await msgStream.CopyToAsync(file);
        }

        var publishingLicenseFromFile = fileHandler.Protection.GetSerializedPublishingLicense();

        /*
         * ================================================== Dump intermediate data: Publishing license read from the file handler, utf16-le (handlers read) ==================================================
         */
        using (var publishingLicenseStream = new MemoryStream([.. publishingLicenseFromFile])) // Guessing this is just the content of [Root Entry]/DataSpaces/TransformInfo/DRMTransform/Primary/IRMDSTransformInfo/XrMLLicense
        {
            await using var file       = File.Open("06.PublishingLicenseFromFile", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);
            await using var prettified = PrettifyMultiRootXml(publishingLicenseStream, Encoding.Unicode);

            await prettified.CopyToAsync(file);
        }

        /*
         * ================================================== Initialize MIP: Protection (handlers read) ==================================================
         */
        var publishingLicenseInfoFromFile = PublishingLicenseInfo.GetPublishingLicenseInfo(publishingLicenseFromFile, mipContext);

        using var protectionProfile  = await BuildProtectionProfileAsync(mipContext, CacheStorageType.OnDisk, consentDelegate);
        using var protectionEngine   = await BuildProtectionEngineAsync(protectionProfile, Inputs.AppId, Inputs.UserId, authDelegate, Inputs.Locale);
        using var consumptionHandler = await protectionEngine.CreateProtectionHandlerForConsumptionAsync(new ConsumptionSettings(publishingLicenseInfoFromFile));

        /*
         * ================================================== Decrypt using MIP consumption protection handler, the data is corrupted on 4k superblock boundaries because of wrong IV calculation (handlers read) ==================================================
         */
        var contentsData  = contents.ToArray();
        var cleartextData = new byte[contentsData.Length];
        var decrypted     = consumptionHandler.DecryptBuffer(0, contentsData, cleartextData, false); // isFinal == true: Microsoft.InformationProtection.Exceptions.InternalException: 'AESCryptoWriter: Failed to transform final block'
        //  ^^^ decrypted length is useless, as it just reflects the input length

        /*
         * ================================================== Dump final data: DRMContent.Contents (cleartext), should represent the protected message CFB, if not corrupted (handlers read) ==================================================
         */
        await using (var file = File.Open("07.ContentsDecryptedByHandler", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await file.WriteAsync(cleartextData.AsMemory(0, (int)cleartextLength));
        }

        /*
         * ================================================== Compute seeds used fo superblock IV calculation ==================================================
         */
        var ivValues = await AnalyzeOriginalIvValuesAsync(Inputs.HackDecryptionKey, "02.ContentsEncrypted", "03.ContentsDecryptedManually", "07.ContentsDecryptedByHandler");
        await using (var file = File.Open("08.InitVectorSeeds", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await DumpIvValuesAsync(file, ivValues);
        }

        /*
         * ================================================== Decrypt using MIP consumption protection handler, but try to compensate the incorrect IV calculation for superblocks (handlers read) ==================================================
         */
        var ciphertextBlock = new byte[SuperblockSize]; // Should correspond to consumptionHandler.BlockSize
        var cleartextBlock  = new byte[SuperblockSize];
        var offset          = 0L;

        while (offset < contentsData.Length)
        {
            Buffer.BlockCopy(contentsData, (int)offset, ciphertextBlock, 0, SuperblockSize);

            var fakeOffset = offset * SuperblockSize; // Compensate the incorrect IV calculation
            _ = consumptionHandler.DecryptBuffer(fakeOffset, ciphertextBlock, cleartextBlock, false);

            Buffer.BlockCopy(cleartextBlock, 0, cleartextData, (int)offset, SuperblockSize);
            offset += SuperblockSize;
        }
        await using (var file = File.Open("09.ContentsDecryptedByHandlerCompensated", FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await file.WriteAsync(cleartextData.AsMemory(0, (int)cleartextLength));
        }
    }




    private static Stream ReadCompressedBlock(Stream rpmsg, bool leaveOpen = true)
    {
        using var reader = new BinaryReader(rpmsg, Encoding.Default, leaveOpen);
        return reader.ReadRpMsgCompressedBlock();
    }

    private static async ValueTask<Stream> DecompressAsync(Stream compressed, bool leaveOpen = true, CancellationToken cancellationToken = default)
    {
        var decompressed = new MemoryStream();
        await using var zlib = new ZLibStream(compressed, CompressionMode.Decompress, leaveOpen);
        await zlib.CopyToAsync(decompressed, cancellationToken);
        decompressed.Position = 0;

        return decompressed;
    }

    private static long ReadContentsLength(Stream drmContentStream)
    {
        using var reader = new BinaryReader(drmContentStream, Encoding.Default, true);
        var cleartextLength = (long)reader.ReadUInt64();
        return cleartextLength;
    }

    private static async ValueTask<Stream> HackDecryptUsingKnownKeyAsync(Stream encrypted, byte[] key, long cleartextLength, CancellationToken cancellationToken = default)
    {
        var cleartextStream = new MemoryStream();

        using (var aes = Aes.Create())
        {
            aes.Mode    = CipherMode.CBC;
            aes.KeySize = key.Length * 8;
            aes.Key     = key;
            aes.Padding = PaddingMode.None;

            var buffer = new byte[SuperblockSize];
            var blockNumber = 0u;
            while (encrypted.Position < encrypted.Length)
            {
                aes.IV = HackCalculateIv(blockNumber * SuperblockSize, key);

                using var decryptor = aes.CreateDecryptor();
                await using var cryptoStream = new CryptoStream(encrypted, decryptor, CryptoStreamMode.Read, leaveOpen: true);
                var read = await cryptoStream.ReadAsync(buffer, cancellationToken);
                if (read != buffer.Length) throw new InvalidOperationException("Unexpected input superblock alignment.");

                await cleartextStream.WriteAsync(buffer, cancellationToken);
                ++blockNumber;
            }
        }

        cleartextStream.SetLength(cleartextLength);
        cleartextStream.Position = 0;

        return cleartextStream;
    }

    private static byte[] HackCalculateIv(uint blockOffset, byte[] key)
    {
        var iv = new byte[AesBlockSize];
        using var aes = Aes.Create();

        aes.Mode    = CipherMode.ECB;
        aes.KeySize = key.Length * 8;
        aes.Key     = key;
        aes.IV      = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        aes.Padding = PaddingMode.None;

        var blockOffsetInput = new byte[AesBlockSize];
        BinaryPrimitives.WriteUInt32LittleEndian(blockOffsetInput, blockOffset);

        using var encryptor = aes.CreateEncryptor();
        encryptor.TransformBlock(blockOffsetInput, 0, blockOffsetInput.Length, iv, 0);

        return iv;
    }

    private static ApplicationInfo BuildAppInfo(string appId, string appName, string appVersion)
    {
        var appInfo = new ApplicationInfo{ ApplicationId = appId, ApplicationName = appName, ApplicationVersion = appVersion };
        return appInfo;
    }

    private static MipContext BuildMipContext(ApplicationInfo appInfo, string localStoragePath)
    {
        var mipConfig = new MipConfiguration(appInfo, localStoragePath, LogLevel.Info, isOfflineOnly: false, CacheStorageType.OnDisk)
        {
            DiagnosticOverride = new DiagnosticConfiguration
            {
                IsMinimalTelemetryEnabled = true,
                IsAuditPriorityEnhanced   = false,
                IsLocalCachingEnabled     = true,
                IsTraceLoggingEnabled     = false,
            },
        };
        var mipContext = MIP.CreateMipContext(mipConfig);

        return mipContext;
    }

    private static async Task<IFileProfile> BuildFileProfileAsync(MipContext mipContext, CacheStorageType mipProfileCache, IConsentDelegate consent)
    {
        MIP.Initialize(MipComponent.File);
        var fileProfileSettings = new FileProfileSettings(mipContext, mipProfileCache, consent);
        var fileProfile = await MIP.LoadFileProfileAsync(fileProfileSettings);

        return fileProfile;
    }

    private static async Task<IFileEngine> BuildFileEngineAsync(IFileProfile profile, string userId, IAuthDelegate authDelegate, string locale)
    {
        var fileEngineSettings = new FileEngineSettings($"{userId}'s file engine", authDelegate, string.Empty, locale)
        {
            Identity             = new Identity(userId),
            CustomSettings       = [new(CustomSettings.EnableMsgFileType, "true")],
            LoadSensitivityTypes = true,
        };

        var fileEngine = await profile.AddEngineAsync(fileEngineSettings);

        return fileEngine;
    }

    private static async Task<IProtectionProfile> BuildProtectionProfileAsync(MipContext mipContext, CacheStorageType mipProfileCache, IConsentDelegate consent)
    {
        MIP.Initialize(MipComponent.Protection);
        var protectionProfileSettings = new ProtectionProfileSettings(mipContext, mipProfileCache, consent);
        var protectionProfile = await MIP.LoadProtectionProfileAsync(protectionProfileSettings);

        return protectionProfile;
    }

    private static async Task<IProtectionEngine> BuildProtectionEngineAsync(IProtectionProfile profile, string appId, string userId, IAuthDelegate authDelegate, string locale)
    {
        var protectionEngineSettings = new ProtectionEngineSettings($"{userId}'s protection engine", authDelegate, string.Empty, locale)
        {
            Identity                = new Identity(userId),
            CustomSettings          = [new(CustomSettings.EnableMsgFileType, "true")],
            UnderlyingApplicationId = appId,
        };

        var protectionEngine = await profile.AddEngineAsync(protectionEngineSettings);

        return protectionEngine;
    }

    public static Stream PrettifyMultiRootXml(Stream xml, Encoding encoding)
    {
        var readerSettings = new XmlReaderSettings
        {
            ConformanceLevel = ConformanceLevel.Fragment,
            IgnoreWhitespace = true,
        };

        var writerSettings = new XmlWriterSettings
        {
            Indent             = true,
            IndentChars        = "    ",
            NewLineChars       = "\r\n",
            NewLineHandling    = NewLineHandling.Replace,
            OmitXmlDeclaration = true
        };

        var outputStream = new MemoryStream();
        using var sr     = new StreamReader(xml, encoding);
        using var reader = XmlReader.Create(sr, readerSettings);

        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element) continue;

            var node = XNode.ReadFrom(reader);
            using var sw = new StreamWriter(outputStream, leaveOpen: true);
            using var writer = XmlWriter.Create(sw, writerSettings);
            node.WriteTo(writer);
            sw.WriteLine();
        }
        outputStream.Position = 0;

        return outputStream;
    }

    private static async ValueTask<IReadOnlyCollection<(byte[] Correct, byte[] Incorrect)>> AnalyzeOriginalIvValuesAsync(byte[] key, string ciphertextFilename, string manualCleartextFilename, string handlerCleartextFilename)
    {
        var result = new List<(byte[] Correct, byte[] Incorrect)>();

        using var aes = BuildSimpleAes(key);

        await using var ciphertextFile       = File.Open(ciphertextFilename      , FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        await using var manualCleartextFile  = File.Open(manualCleartextFilename , FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        await using var handlerCleartextFile = File.Open(handlerCleartextFilename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);


        var block  = new byte[AesBlockSize];
        var offset = 0L;

        while (offset < ciphertextFile.Length)
        {
            ciphertextFile.Position = manualCleartextFile.Position = handlerCleartextFile.Position = offset;

            // Read first block of the superblock of the ciphertext
            await ciphertextFile.ReadExactlyAsync(block, 0, block.Length);
            var preIvCleartext = DecryptBlock(aes, block);

            // Read first block of the superblock of the cleartext (manually decrypted, thus correct)
            await manualCleartextFile.ReadExactlyAsync(block, 0, block.Length);
            var ivCorrect     = XorBlocks(preIvCleartext, block);
            var ivCorrectSeed = DecryptBlock(aes, ivCorrect);

            // Read first block of the superblock of the cleartext (handler decrypted, thus incorrect)
            await handlerCleartextFile.ReadExactlyAsync(block, 0, block.Length);
            var ivIncorrect     = XorBlocks(preIvCleartext, block);
            var ivIncorrectSeed = DecryptBlock(aes, ivIncorrect);

            result.Add((ivCorrectSeed, ivIncorrectSeed));

            offset += SuperblockSize;
        }

        return result;
    }

    private static byte[] DecryptBlock(Aes aes, byte[] cipherText)
    {
        var clearText = new byte[AesBlockSize];
        using var decryptor = aes.CreateDecryptor();
        decryptor.TransformBlock(cipherText, 0, cipherText.Length, clearText, 0);

        return clearText;
    }

    private static byte[] XorBlocks(byte[] block1, byte[] block2)
    {
        var length = Math.Max(block1.Length, block2.Length);
        var xor = new byte[length];

        for (var i = 0; i < length; ++i)
        {
            var b1 = i < block1.Length ? block1[i] : 0;
            var b2 = i < block2.Length ? block2[i] : 0;
            xor[i] = (byte)(b1 ^ b2);
        }

        return xor;
    }

    private static Aes BuildSimpleAes(byte[] key)
    {
        var aes = Aes.Create();

        aes.Mode    = CipherMode.ECB;
        aes.KeySize = key.Length * 8;
        aes.Key     = key;
        aes.IV      = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        aes.Padding = PaddingMode.None;

        return aes;
    }

    private static bool TryGetUnsignedLongLe(byte[] data, out ulong? value)
    {
        value = null;
        if (data.Length > 8 && data[8 ..].Any(d => d > 0)) return false;

        value = BinaryPrimitives.ReadUInt64LittleEndian(data);
        return true;
    }

    private static async ValueTask DumpIvValuesAsync(Stream file, IReadOnlyCollection<(byte[] Correct, byte[] Incorrect)> ivValues)
    {
        const string BiggerThan64Bits = "<more than 64 bits>";
        await using var writer = new StreamWriter(file, leaveOpen: true);

        await writer.WriteLineAsync("Correct\tIncorrect");
        foreach (var (correct, incorrect) in ivValues)
        {
            var correctText   = TryGetUnsignedLongLe(correct  , out var correctValue  ) ? $"0x{correctValue:x16}"   : BiggerThan64Bits;
            var incorrectText = TryGetUnsignedLongLe(incorrect, out var incorrectValue) ? $"0x{incorrectValue:x16}" : BiggerThan64Bits;

            await writer.WriteLineAsync($"{correctText}\t{incorrectText}");
        }
    }
}





internal static class BinaryReaderExtensions
{
    public static Stream ReadRpMsgCompressedBlock(this BinaryReader reader)
    {
        const ulong Signature = 0x86e311c46004e876;
        const uint Check      = 0x00000fa0;

        var signature = reader.ReadUInt64();
        if (signature != Signature) throw new InvalidDataException($"Invalid RPMSG signature {signature:x16}.");

        var compressedData = new MemoryStream();
        var block = 0;

        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            var check = reader.ReadUInt32();
            if (check != Check) throw new InvalidDataException($"Invalid RPMSG check {check:x8} at block {block}.");

            var sizeAfterInflation  = reader.ReadUInt32(); // Not sure if it does make any sense to verify the block size after inflation (maybe if there are multiple compression algorithms?).
            var sizeBeforeInflation = reader.ReadUInt32();
            var segment             = new byte[sizeBeforeInflation];
            var read                = reader.Read(segment, 0, (int)sizeBeforeInflation);

            if (read < sizeBeforeInflation) throw new InvalidDataException($"Unexpected end of data after reading {read} bytes (instead of {sizeBeforeInflation}).");
            compressedData.Write(segment, 0, read);

            ++block;
        }

        compressedData.Position = 0;

        return compressedData;
    }
}

internal class AuthDelegate(ApplicationInfo appInfo) : IAuthDelegate
{
    public string AcquireToken(Identity identity, string authority, string resource, string claims)
    {
        var scopes    = new[]{ resource[^1].Equals('/') ? $"{resource}.default" : $"{resource}/.default" };
        var clientApp = PublicClientApplicationBuilder.Create(appInfo.ApplicationId).WithAuthority(authority).WithDefaultRedirectUri().Build();
        var accounts  = clientApp.GetAccountsAsync().GetAwaiter().GetResult();
        var result    = clientApp
            .AcquireTokenInteractive(scopes)
            .WithAccount(accounts.FirstOrDefault())
            .WithPrompt(Prompt.NoPrompt)
            .WithLoginHint(identity.Email)
            .ExecuteAsync()
            .ConfigureAwait(false)
            .GetAwaiter().GetResult();

        return result.AccessToken;
    }
}

internal class ConsentDelegate : IConsentDelegate
{
    public Consent GetUserConsent(string url) => Consent.Accept;
}