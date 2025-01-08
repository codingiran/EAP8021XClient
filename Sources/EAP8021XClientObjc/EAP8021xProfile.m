//
//  EAP8021xProfile.m
//  EAP8021XClient
//
//  Created by CodingIran on 2025/1/8.
//

#import "EAP8021xProfile.h"
#include "EAPOLClientConfiguration.h"
#include "EAPUtil.h"

@implementation EAP8021xProfile

+ (nullable NSString *)eapTypeToString:(EAP8021xEAPType)eapType {
    uint32_t type = (uint32_t)eapType;
    const char *str = EAPTypeStr(type);
    if (strcmp(str, "<unknown>") == 0) {
        return nil;
    }
    return [NSString stringWithUTF8String:str];
}

+ (EAP8021xSecurityType)stringToSecurityType:(NSString *)securityType {
    if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWEP]) {
        return EAP8021xSecurityTypeWEP;
    } else if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA]) {
        return EAP8021xSecurityTypeWPA;
    } else if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA2]) {
        return EAP8021xSecurityTypeWPA2;
    } else if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeAny]) {
        return EAP8021xSecurityTypeAny;
    }
    return EAP8021xSecurityTypeUnknown;
}

+ (nullable NSString *)securityTypeToString:(EAP8021xSecurityType)securityType {
    switch (securityType) {
        case EAP8021xSecurityTypeWEP:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWEP;
        case EAP8021xSecurityTypeWPA:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA;
        case EAP8021xSecurityTypeWPA2:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA2;
        case EAP8021xSecurityTypeAny:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeAny;
        default:
            return nil;
    }
}

+ (EAP8021TTLSInnerAuthType)stringToTTLSInnerAuthType:(NSString *)authType {
    if ([authType isEqualToString:@"PAP"]) {
        return EAP8021TTLSInnerAuthTypePAP;
    } else if ([authType isEqualToString:@"CHAP"]) {
        return EAP8021TTLSInnerAuthTypeCHAP;
    } else if ([authType isEqualToString:@"MSCHAP"]) {
        return EAP8021TTLSInnerAuthTypeMSCHAP;
    } else if ([authType isEqualToString:@"MSCHAPv2"]) {
        return EAP8021TTLSInnerAuthTypeMSCHAPv2;
    } else {
        return EAP8021TTLSInnerAuthTypeUnknown;
    }
}

+ (nullable NSString *)ttlsInnerAuthTypeToString:(EAP8021TTLSInnerAuthType)authType {
    switch (authType) {
        case EAP8021TTLSInnerAuthTypePAP:
            return @"PAP";
        case EAP8021TTLSInnerAuthTypeCHAP:
            return @"CHAP";
        case EAP8021TTLSInnerAuthTypeMSCHAP:
            return @"MSCHAP";
        case EAP8021TTLSInnerAuthTypeMSCHAPv2:
            return @"MSCHAPv2";
        default:
            return nil;
    }
}

@end


