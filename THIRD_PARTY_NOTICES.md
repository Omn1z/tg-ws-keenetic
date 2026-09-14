# Third-party notices

This project contains a Rust port of network behavior from Flowseal/tg-ws-proxy
v1.10.2, revision f200e33fd283143a9f101d62aaf9d8c1468a23fe (MIT), and references
the Go router port in Omn1z/nfqws2-keenetic-strategy-selector. The original
upstream license is reproduced in LICENSE.upstream.

Rust dependency versions and transitive dependencies are pinned in Cargo.lock.
They include Tokio, RustCrypto AES/CTR/SHA/HMAC, rand, serde/serde_json, base64,
subtle, socket2 and native-tls/tokio-native-tls. See each dependency's distributed
license and Cargo package metadata for the applicable terms.

Linux release binaries statically link OpenSSL through openssl-src. OpenSSL 3
is licensed under Apache-2.0. The release packaging includes the OpenSSL license
alongside this project's MIT license and the upstream notice. Native Windows
development builds use Schannel and native macOS builds use Security Framework.

MIPS/MIPSEL cross builds also use the GCC 9.2 static runtime and GNU unwinder
from the recorded cross toolchain image. These runtime libraries are covered
by GPLv3 with the GCC Runtime Library Exception. The MIPS release archives
include the corresponding texts as licenses/GCC-COPYING3 and
licenses/GCC-COPYING.RUNTIME; build metadata records their source and hashes.
