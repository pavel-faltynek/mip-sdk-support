Problem 1:

- `IProtectionHandler.DecryptBuffer()` does not work correctly.

Problem 2:

- `IFileHandler.GetDecryptedTemporaryStreamAsync()` returns invalid data.

Problem 3:

- `IProtectionHandler.DecryptBuffer()` does not accept `isFinal = true`

General reproduction steps:

1. Setup/Enable Purview on the tenant.
2. Create encryption label L.
3. From a Purview-aware client (eg. web outlook):
    1. Compose an email message, attach two attachments, arbitrary file type at least 1MB and 2MB in size.
    2. Mark the message with the label L and send it to recipient R.
    3. Verify, the message can be read at R.
4. In a Purview-unaware client:
    1. Verify the message has been received for R and download the attachment `message_v2.rpmsg`
5. In a development environment (e.g. C# IDE):
    1. Use the latest [MIP SDK wrapper nuget (1.17.158)][link-nuget].
    2. Create the whole chain of profile/engine and file handler from the `rpmsg` file.
    3. Convert to msg format via `GetDecryptedTemporaryStreamAsync()`.
6. In a development environment (e.g. C# IDE):
    1. Use the latest [MIP SDK wrapper nuget (1.17.158)][link-nuget].
    2. Create the whole chain of profile/engine and file handler from the `rpmsg` file.
    3. Extract the publishing license info using the file handler.
    4. Create the whole chain of profile/engine and protection handler for consumption using the previously extracted publishing license info.
    5. Extract the `DRMContent` stream from the `rpmsg` CFB (after its inflation).
    6. Decrypt the `DRMContent` stream via `IProtectionHandler.DecryptBuffer()`.
    7. Try to pass `true` to `isFinal` for the last block (or for the whole stream, if passing as a whole) during the `DRMContent` stream decryption via `IProtectionHandler.DecryptBuffer()`.

Actual results:

- According to 5.iii, observe the invalid header in the root properties stream in the msg CFB.
- According to 6.vi:
    - Observe the produced clear text stream "seems" to be correct, but double-check it isn't.
    - At the beginnings of "superblocks" (4k blocks) there is always 16 corrupted bytes (except the first superblock).
- According to 6.vii: exception is thrown (`Microsoft.InformationProtection.Exceptions.InternalException: 'AESCryptoWriter: Failed to transform final block'`).

Problems in the MIP SDK:

- According to 5.iii, there is just wrong header, because substorage headers should be formatted this way, as oposite to root headers, where additional padding (Reserved field) is expected.
- According to 6.vi
    - Every time the superblock gets decrypted, initialization vector (IV) must be computed, unfortunately, it is computed in wrong way.
    - Accidentally, the first block IV is correct, as the method actually used has the same result as the method which should be used for input of 0.
    - The IV SHOULD get computed as `AES128ECB.Encrypt(superblock_offset, key)`, but it's computed as `AES128ECB.Encrypt(superblock_number, key)`.
- According to 6.vii, I'm not sure, but I can probably live with it now (not sure, if this doesn't turn into bigger problem during encryption phase).

Resolution:

- According to 5.iii, just generate a correct header, which means writing additional 8 bytes of zero value.
- According to 6.vi
    - Use the same IV calculation as is already used in `IFileHandler.GetDecryptedTemporaryStreamAsync()` internally - because it's just able to decrypt the `rpmsg` with no problem.
    - Check also the `EncryptBuffer` function, where the same problem might be located too.
- According to 6.vii, not sure.

Proof for the resolution according to the 6.vi:

- Extract the decryption key for the appropriate file/user/tenant from the MIP SDK sqlite file cache.
- Manually decrypt the `DRMContent` per 4k blocks by `AES256CBC` using the extracted key.
- Compute the IV for each block as described above (Problems in the MIP SDK).
- Observe fully valid data (CFB with the protected content).

Applicable workarounds:

- According to 6.vi
    - Decrypt content per superblocks.
    - Pass the fake offset computed as offset * superblock-length.
    - Hope there is no bit truncation on the passed value down the road and the encrypted data is relatively small (that 4096 x length doesn't overflow 32bit value).

Notes:

- As usual, I don't expect everyone will understand the above, but it's critical to pass this info to someone who is able to make changes in the MIP SDK source and verify/confirm these reports.
- To complete the goal, which is "reading/writing" the `rpmsg` files, we definitely need fully working MIP SDK for both decryption (phase 1) and encryption (phase 2).

[link-nuget]: https://www.nuget.org/packages/Microsoft.InformationProtection.File/1.17.158
