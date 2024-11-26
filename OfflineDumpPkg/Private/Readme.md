# OpenSSL Redirection Headers

At present, we need OpenSSL functionality that is not exposed by BaseCryptLib.

- AES-ECB (used as a step in implementing AES-CTR).
- Enveloped-message CMS (encrypted key transport).

At present, we are leveraging BaseCryptLib's port of OpenSSL. To do this, we need to redirect `#include <openssl/FILE.h>` to the appropriate full path. Since EDK2's build system doesn't allow direct manipulation of the include paths, we use stub headers to perform this redirection.

This isn't ideal. The long-term solution would be to update BaseCryptLib to support the necessary APIs.
