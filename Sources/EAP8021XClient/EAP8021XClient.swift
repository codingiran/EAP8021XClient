import Foundation

// Enforce minimum Swift version for all platforms and build systems.
#if swift(<5.5)
#error("EAP8021XClient doesn't support Swift versions below 5.5.")
#endif

/// Current EAP8021XClient version 0.0.1. Necessary since SPM doesn't use dynamic libraries. Plus this will be more accurate.
let version = "0.1.0"

public enum EAP8021XClient {}
