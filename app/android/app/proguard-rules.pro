# SPDX-License-Identifier: AGPL-3.0-or-later
#
# R8 rules for the release APK.
#
# androidx.security-crypto (which holds the remembered passphrase in the
# Keystore) is built on Google Tink, and Tink's classes are annotated with
# Error Prone annotations that are compile-time only — they are deliberately not
# shipped in any artifact. R8 sees the references, cannot resolve them, and
# fails the build.
#
# These are annotations: nothing reads them at runtime, so there is nothing to
# keep. Telling R8 not to warn about them is the whole fix, and it is what
# Tink's own documentation asks consumers to do.
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**

# Tink also carries KeysDownloader, which fetches keysets over HTTP using the
# Google API client. NullChat never calls it — the keyset is generated on the
# device and never leaves it, and this app has no business making an HTTP
# request outside Tor. The classes are simply absent, which is correct; R8 only
# needs telling that their absence is not a mistake.
-dontwarn com.google.api.client.**
-dontwarn com.google.api.**
-dontwarn org.joda.time.**

# Tink loads key managers by reflection from its registry, so the classes it
# instantiates must survive shrinking even though nothing references them by
# name. Without this the app builds and then fails at the first attempt to open
# the keystore, which is a far worse failure than a build error.
-keep class com.google.crypto.tink.** { *; }
-keep class androidx.security.crypto.** { *; }
