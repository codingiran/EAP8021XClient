#ifdef __OBJC__
#import <Cocoa/Cocoa.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "EAPOLClientWrapper.h"
#import "SecTrustedApplicationPriv.h"

FOUNDATION_EXPORT double EAP8021XClientVersionNumber;
FOUNDATION_EXPORT const unsigned char EAP8021XClientVersionString[];

