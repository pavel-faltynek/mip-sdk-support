Problem 1:
    - IProtectionHandler.DecryptBuffer() does not work correctly.

Problem 2:
    - IFileHandler.GetDecryptedTemporaryStreamAsync() returns invalid data.

Problem 3:
    - IProtectionHandler.DecryptBuffer() does not accept isFinal = true

General reproduction steps:
    1) Setup/Enable Purview on the tenant.
    2) Create encryption label L.
    3) From a Purview-aware client (eg. web outlook):
        a) Compose an email message, attach two attachments, arbitrary file type at least 1MB and 2MB in size.
        b) Mark the message with the label L and send it to recipient R.
        c) Verify, the message can be read at R.
    4) In a Purview-unaware client:
        a) Verify the message has been received for R and download the attachment message_v2.rpmsg
    5) In a development environment (e.g. C# IDE):
        a) Use the latest MIP SDK wrapper nuget (1.17.158).
        b) Create the whole chain of profile/engine and file handler from the rpmsg file.
        c) Convert to msg format via GetDecryptedTemporaryStreamAsync().
    6) In a development environment (e.g. C# IDE):
        a) Use the latest MIP SDK wrapper nuget (1.17.158).
        b) Create the whole chain of profile/engine and file handler from the rpmsg file.
        c) Extract the publishing license info using the file handler.
        d) Create the whole chain of profile/engine and protection handler for consumption using the previously extracted publishing license info.
        e) Extract the DRMContent stream from the rpmsg CFB (after its inflation).
        f) Decrypt the DRMContent stream via IProtectionHandler.DecryptBuffer().
        g) Try to pass true to isFinal for the last block (or for the whole stream, if passing as a whole) during the DRMContent stream decryption via IProtectionHandler.DecryptBuffer().

Actual results:
    - According to 5.c, observe the invalid header in the root properties stream in the msg CFB.
    - According to 6.f:
        - Observe the produced clear text stream "seems" to be correct, but double-check it isn't.
        - At the beginnings of "superblocks" (4k blocks) there is always 16 corrupted bytes (except the first superblock).
    - According to 6.g: exception is thrown (something like "cannot transform final block").

Problems in the MIP SDK:
    - According to 5.c, there is just wrong header, because substorage headers should be formatted this way, as oposite to root headers, where additional padding (Reserved field) is expected.
    - According to 6.f
        - Every time the superblock gets decrypted, initialization vector (IV) must be computed, unfortunately, it is computed in wrong way.
        - Accidentally, the first block IV is correct, as the method actually used has the same result as the method which should be used for input of 0.
        - The IV SHOULD get computed as AES128ECB.Encrypt(superblock_offset, key), but it's probably computed as AES128.Encrypt(superblock_number, key).
    - According to 6.g, I'm not sure, but I can probably live with it now (not sure, if this doesn't turn into bigger problem during encryption phase).

Resolution:
    - According to 5.c, just generate a correct header, which means writing additional 8 bytes of zero value.
    - According to 6.f
        - Use the same IV calculation as is already used in IFileHandler.GetDecryptedTemporaryStreamAsync() internally - because it's just able to decrypt the rpmsg with no problem.
        - Check the EncryptBuffer function, where the same problem might be located too.
    - According to 6.g, not sure.

Proof for the resolution according to the 6.f:
    - Extract the decryption key for the appropriate file/user/tenant from the MIP SDK sqlite file cache.
    - Manually decrypt the DRMContent per 4k blocks by AES256CBC using the extracted key.
    - Compute the IV for each block as described above (Problems in the MIP SDK).
    - Observe fully valid data (CFB with the protected content).

Notes:
    - As usual, I don't expect everyone will understand the above, but it's critical to pass this info to someone who is able to make changes in the MIP SDK source and verify/confirm these reports.
    - To complete the goal, which is "reading/writing" the rpmsg files, we definitely need fully working MIP SDK for both decryption (phase 1) and encryption (phase 2).
