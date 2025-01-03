//
//  Eap8021x.m
//  wifi_connect
//
//  Created by CodingIran on 2024/12/31.
//

#import "Eap8021x.h"
#import <Foundation/Foundation.h>
#include "EAPOLClientConfiguration.h"
#include "EAPOLClientConfigurationPrivate.h"
#include "EAPClientProperties.h"
#include "EAPUtil.h"
#include "EAPCertificateUtil.h"
#include "myCFUtil.h"

@implementation Eap8021xProfile

+ (nullable NSString *)eapTypeToString:(Eap8021xEAPType)eapType {
    uint32_t type = (uint32_t)eapType;
    const char *str = EAPTypeStr(type);
    if (strcmp(str, "<unknown>") == 0) {
        return nil;
    }
    return [NSString stringWithUTF8String:str];
}

+ (Eap8021xSecurityType)stringToSecurityType:(NSString *)securityType {
    if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWEP]) {
        return Eap8021xSecurityTypeWEP;
    } else if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA]) {
        return Eap8021xSecurityTypeWPA;
    } else if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA2]) {
        return Eap8021xSecurityTypeWPA2;
    } else if ([securityType isEqualToString:(__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeAny]) {
        return Eap8021xSecurityTypeAny;
    }
    return Eap8021xSecurityTypeUnknown;
}

+ (nullable NSString *)securityTypeToString:(Eap8021xSecurityType)securityType {
    switch (securityType) {
        case Eap8021xSecurityTypeWEP:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWEP;
        case Eap8021xSecurityTypeWPA:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA;
        case Eap8021xSecurityTypeWPA2:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeWPA2;
        case Eap8021xSecurityTypeAny:
            return (__bridge NSString *)kEAPOLClientProfileWLANSecurityTypeAny;
        default:
            return nil;
    }
}

+ (Eap8021TTLSInnerAuthType)stringToTTLSInnerAuthType:(NSString *)authType {
    if ([authType isEqualToString:@"PAP"]) {
        return Eap8021TTLSInnerAuthTypePAP;
    } else if ([authType isEqualToString:@"CHAP"]) {
        return Eap8021TTLSInnerAuthTypeCHAP;
    } else if ([authType isEqualToString:@"MSCHAP"]) {
        return Eap8021TTLSInnerAuthTypeMSCHAP;
    } else if ([authType isEqualToString:@"MSCHAPv2"]) {
        return Eap8021TTLSInnerAuthTypeMSCHAPv2;
    } else {
        return Eap8021TTLSInnerAuthTypeUnknown;
    }
}

+ (nullable NSString *)ttlsInnerAuthTypeToString:(Eap8021TTLSInnerAuthType)authType {
    switch (authType) {
        case Eap8021TTLSInnerAuthTypePAP:
            return @"PAP";
        case Eap8021TTLSInnerAuthTypeCHAP:
            return @"CHAP";
        case Eap8021TTLSInnerAuthTypeMSCHAP:
            return @"MSCHAP";
        case Eap8021TTLSInnerAuthTypeMSCHAPv2:
            return @"MSCHAPv2";
        default:
            return nil;
    }
}

@end

@implementation Eap8021x

+ (nullable Eap8021xProfile *)profileWithProfileId:(nullable NSString *)profileId {
    if (profileId == nil || profileId.length == 0) {
        return nil;
    }
    CFStringRef profile_id = CFStringCreateWithCString(NULL, [profileId UTF8String], kCFStringEncodingUTF8);
    if (profile_id == NULL) {
        return nil;
    }
    EAPOLClientConfigurationRef cfg = [self openConfiguration:false];
    if (cfg == NULL) {
        my_CFRelease(&profile_id);
        return nil;
    }
    EAPOLClientProfileRef profileRef = EAPOLClientConfigurationGetProfileWithID(cfg, profile_id);
    if (profileRef == NULL) {
        my_CFRelease(&profile_id);
        my_CFRelease(&cfg);
        return nil;
    }
    Eap8021xProfile *profileModel = [self profileWithProfileRef:profileRef];
    my_CFRelease(&profile_id);
    my_CFRelease(&cfg);
    my_CFRelease(&profileRef);
    return profileModel;
}

+ (nullable Eap8021xProfile *)profileWithSSID:(nullable NSString *)ssid {
    if (ssid == nil || ssid.length == 0) {
        return nil;
    }
    NSData *ssidData = [ssid dataUsingEncoding:NSUTF8StringEncoding];
    CFDataRef ssid_data = NULL;
    if (ssidData != nil && ssidData.length > 0) {
        ssid_data = CFDataCreate(kCFAllocatorDefault, [ssidData bytes], [ssidData length]);
    }
    if (ssid_data == NULL) {
        return nil;
    }
    EAPOLClientConfigurationRef cfg = [self openConfiguration:false];
    if (cfg == NULL) {
        my_CFRelease(&ssid_data);
        return nil;
    }
    EAPOLClientProfileRef profileRef = EAPOLClientConfigurationGetProfileWithWLANSSID(cfg, ssid_data);
    if (profileRef == NULL) {
        my_CFRelease(&ssid_data);
        my_CFRelease(&cfg);
        return nil;
    }
    Eap8021xProfile *profileModel = [self profileWithProfileRef:profileRef];
    my_CFRelease(&ssid_data);
    my_CFRelease(&cfg);
    return profileModel;
}

+ (nullable NSArray<Eap8021xProfile *> *)listProfiles {
    EAPOLClientConfigurationRef cfg = EAPOLClientConfigurationCreate(NULL);
    if (cfg == NULL) {
        return nil;
    }
    CFArrayRef profiles = EAPOLClientConfigurationCopyProfiles(cfg);
    if (profiles == NULL) {
        return nil;
    }
    CFIndex count = CFArrayGetCount(profiles);
    NSMutableArray *profileModels = [NSMutableArray array];
    for (CFIndex i = 0; i < count; i++) {
        EAPOLClientProfileRef profile = (EAPOLClientProfileRef)CFArrayGetValueAtIndex(profiles, i);
        if (profile == NULL) {
            continue;
        }
        Eap8021xProfile *profileModel = [self profileWithProfileRef:profile];
        [profileModels addObject:profileModel];
        my_CFRelease(&profile);
    }
    my_CFRelease(&cfg);
    return profileModels;
}

+ (nullable Eap8021xProfile *)profileWithProfileRef:(EAPOLClientProfileRef)profileRef {
    if (profileRef == NULL) {
        return nil;
    }
    
    CFDictionaryRef auth_props = EAPOLClientProfileGetAuthenticationProperties(profileRef);
    CFStringRef profileID = EAPOLClientProfileGetID(profileRef);
    CFStringRef userDefinedName = EAPOLClientProfileGetUserDefinedName(profileRef);
    CFStringRef domainName = EAPOLClientProfileGetWLANDomain(profileRef);
    CFStringRef security_type = NULL;
    CFDataRef ssidData = EAPOLClientProfileGetWLANSSIDAndSecurityType(profileRef, &security_type);
    CFArrayRef eap_types =  CFDictionaryGetValue(auth_props, kEAPClientPropAcceptEAPTypes);
    CFStringRef outerIdentity = CFDictionaryGetValue(auth_props, kEAPClientPropOuterIdentity);
    CFStringRef innerAuthentication = CFDictionaryGetValue(auth_props, kEAPClientPropTTLSInnerAuthentication);
    CFArrayRef trustedServerNames = CFDictionaryGetValue(auth_props, kEAPClientPropTLSTrustedServerNames);
    CFArrayRef trustedCertificates = CFDictionaryGetValue(auth_props, kEAPClientPropTLSTrustedCertificates);
    
    Eap8021xProfile *profileModel = [[Eap8021xProfile alloc] init];

    if (profileID != NULL) {
        profileModel.profileId = (__bridge NSString *)profileID;
    }
    if (userDefinedName != NULL) {
        profileModel.userDefinedName = (__bridge NSString *)userDefinedName;
    }
    if (ssidData != NULL) {
        profileModel.ssid = [[NSString alloc] initWithData:(__bridge NSData *)ssidData encoding:NSUTF8StringEncoding];
    }
    if (domainName != NULL) {
        profileModel.domainName = (__bridge NSString *)domainName;
    }
    if (outerIdentity != NULL) {
        profileModel.outerIdentity = (__bridge NSString *)outerIdentity;
    }
    if (innerAuthentication != NULL) {
        profileModel.ttlsInnerAuthType = [Eap8021xProfile stringToTTLSInnerAuthType:(__bridge NSString *)innerAuthentication];
    }
    if (security_type != NULL) {
        profileModel.securityType = [Eap8021xProfile stringToSecurityType:(__bridge NSString *)security_type];
    }
    if (eap_types != NULL) {
        NSMutableArray<NSNumber *> *acceptEAPTypes = [NSMutableArray array];
        for (CFIndex j = 0; j < CFArrayGetCount(eap_types); j++) {
            CFNumberRef type = CFArrayGetValueAtIndex(eap_types, j);
            int val;
            if (isA_CFNumber(type) == NULL || CFNumberGetValue(type, kCFNumberIntType, &val) == FALSE) {
                continue;
            }
            [acceptEAPTypes addObject:[NSNumber numberWithInt:val]];
        }
        profileModel.acceptEAPTypes = acceptEAPTypes;
    }
    if (trustedServerNames != NULL) {
        NSMutableArray<NSString *> *trustedServerName = [NSMutableArray array];
        for (CFIndex j = 0; j < CFArrayGetCount(trustedServerNames); j++) {
            CFStringRef name = CFArrayGetValueAtIndex(trustedServerNames, j);
            if (name != NULL) {
                [trustedServerName addObject:(__bridge NSString *)name];
            }
        }
        profileModel.trustedServerName = trustedServerName;
    }
    if (trustedCertificates != NULL) {
        NSMutableArray<NSData *> *trustedCertificate = [NSMutableArray array];
        for (CFIndex j = 0; j < CFArrayGetCount(trustedCertificates); j++) {
            CFDataRef cert = CFArrayGetValueAtIndex(trustedCertificates, j);
            if (cert != NULL) {
                [trustedCertificate addObject:(__bridge NSData *)cert];
            }
        }
        profileModel.trustedCertificate = trustedCertificate;
    }

    return profileModel;
}


+ (EAPOLClientConfigurationRef)openConfiguration:(BOOL)needAuth {
    if (getuid() == 0 || needAuth == false) {
        return EAPOLClientConfigurationCreate(nil);
    }
    AuthorizationRef auth;
    OSStatus status = AuthorizationCreate(nil, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth);
    if (status != errAuthorizationSuccess) {
        return nil;
    }
    EAPOLClientConfigurationRef cfg = EAPOLClientConfigurationCreateWithAuthorization(NULL, auth);
    return cfg;
}

@end

@implementation Eap8021x (EapAddProfile)

+ (BOOL)createProfileWithEap8021xProfile:(Eap8021xProfile *)eap8021xProfile {
    return [self createProfileWithSSID:eap8021xProfile.ssid
                        acceptEAPTypes:eap8021xProfile.acceptEAPTypes
                       userDefinedName:eap8021xProfile.userDefinedName
                            domainName:eap8021xProfile.domainName
                          securityType:eap8021xProfile.securityType
                         outerIdentity:eap8021xProfile.outerIdentity
               ttlSInnerAuthentication:eap8021xProfile.ttlsInnerAuthType
                     trustedServerName:eap8021xProfile.trustedServerName
                    trustedCertificate:eap8021xProfile.trustedCertificate];
}

+ (BOOL)createProfileWithSSID:(nullable NSString *)ssid
               acceptEAPTypes:(nullable NSArray<NSNumber *> *)acceptEAPTypes
              userDefinedName:(nullable NSString *)userDefinedName
                   domainName:(nullable NSString *)domainName
                 securityType:(Eap8021xSecurityType)securityType
                outerIdentity:(nullable NSString *)outerIdentity
      ttlSInnerAuthentication:(Eap8021TTLSInnerAuthType)ttlSInnerAuthentication
            trustedServerName:(nullable NSArray<NSString *> *)trustedServerName
           trustedCertificate:(nullable NSArray<NSData *> *)trustedCertificate
{
    EAPOLClientConfigurationRef cfg = [self openConfiguration:true];
    if (cfg == NULL) {
        return false;
    }
    
    CFMutableDictionaryRef auth_props = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    // acceptEAPTypes
    if (acceptEAPTypes != nil && acceptEAPTypes.count > 0) {
        CFMutableArrayRef auth_types = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        for (int i = 0; i < acceptEAPTypes.count; i++) {
            int val = [acceptEAPTypes[i] intValue];
            CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &val);
            if (num == NULL) {
                continue;
            }
            CFArrayAppendValue(auth_types, num);
            my_CFRelease(&num);
        }
        CFDictionarySetValue(auth_props, kEAPClientPropAcceptEAPTypes, auth_types);
        my_CFRelease(&auth_types);
    }
    
    // trustedServerName
    if (trustedServerName != nil && trustedServerName.count > 0) {
        CFMutableArrayRef trusted_server_names = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        for (int i = 0; i < trustedServerName.count; i++) {
            NSString *serverName = trustedServerName[i];
            CFStringRef server_name = CFStringCreateWithCString(NULL, [serverName UTF8String], kCFStringEncodingUTF8);
            CFArrayAppendValue(trusted_server_names, server_name);
            my_CFRelease(&server_name);
        }
        CFDictionarySetValue(auth_props, kEAPClientPropTLSTrustedServerNames, trusted_server_names);
        my_CFRelease(&trusted_server_names);
    }
    
    // trustedCertificate
    if (trustedCertificate != nil && trustedCertificate.count > 0) {
        CFMutableArrayRef trusted_certificates = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        for (int i = 0; i< trustedCertificate.count; i++) {
            NSData *certData = trustedCertificate[i];
            CFDataRef cert_data = CFDataCreate(kCFAllocatorDefault, [certData bytes], [certData length]);
            SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, cert_data);
            if (cert == NULL || EAPSecCertificateCopyAttributesDictionary(cert) == NULL) {
                my_CFRelease(&cert_data);
                my_CFRelease(&cert);
            }
            CFArrayAppendValue(trusted_certificates, cert_data);
            my_CFRelease(&cert_data);
            my_CFRelease(&cert);
        }
        CFDictionarySetValue(auth_props, kEAPClientPropTLSTrustedCertificates, trusted_certificates);
        my_CFRelease(&trusted_certificates);
    }
    
    // outerIdentity
    if (outerIdentity != nil && outerIdentity.length > 0) {
        CFStringRef outer_identity = CFStringCreateWithCString(NULL, [outerIdentity UTF8String], kCFStringEncodingUTF8);
        CFDictionarySetValue(auth_props, kEAPClientPropOuterIdentity, outer_identity);
        my_CFRelease(&outer_identity);
    }
    
    // ttlSInnerAuthentication
    NSString *ttlSInnerAuthenticationStr = [Eap8021xProfile ttlsInnerAuthTypeToString:ttlSInnerAuthentication];
    if (ttlSInnerAuthenticationStr != nil && ttlSInnerAuthenticationStr.length > 0) {
        CFStringRef ttlS_inner_authentication = CFStringCreateWithCString(NULL, [ttlSInnerAuthenticationStr UTF8String], kCFStringEncodingUTF8);
        CFDictionarySetValue(auth_props, kEAPClientPropTTLSInnerAuthentication, ttlS_inner_authentication);
        my_CFRelease(&ttlS_inner_authentication);
    }
    
    EAPOLClientProfileRef profile = EAPOLClientProfileCreate(cfg);
    
    NSData *ssidData = [ssid dataUsingEncoding:NSUTF8StringEncoding];
    CFDataRef ssid_data = NULL;
    if (ssidData != nil && ssidData.length > 0) {
        ssid_data = CFDataCreate(kCFAllocatorDefault, [ssidData bytes], [ssidData length]);
    }
    
    CFStringRef domain_name = NULL;
    if (domainName != nil && domainName.length > 0) {
        domain_name = CFStringCreateWithCString(NULL, [domainName UTF8String], kCFStringEncodingUTF8);
    }
    
    // userDefinedName
    CFStringRef user_defined_name = NULL;
    if (userDefinedName != nil && userDefinedName.length > 0) {
        user_defined_name = CFStringCreateWithCString(NULL, [userDefinedName UTF8String], kCFStringEncodingUTF8);
    } else if (ssid != nil && ssid.length > 0) {
        user_defined_name = CFStringCreateWithCString(NULL, [ssid UTF8String], kCFStringEncodingUTF8);
    } else if (domainName != nil && domainName.length > 0) {
        user_defined_name = domain_name;
    } else {
        user_defined_name = EAPOLClientProfileGetID(profile);
    }
    if (user_defined_name != NULL) {
        EAPOLClientProfileSetUserDefinedName(profile, user_defined_name);
        my_CFRelease(&user_defined_name);
    }
    
    EAPOLClientProfileSetAuthenticationProperties(profile, auth_props);
    
    // securityType
    NSString *securityTypeStr = [Eap8021xProfile securityTypeToString:securityType];
    CFStringRef security_type = NULL;
    if (securityTypeStr != nil && securityTypeStr.length > 0) {
        security_type = CFStringCreateWithCString(NULL, [securityTypeStr UTF8String], kCFStringEncodingUTF8);
    }
    if (security_type == NULL) {
        my_CFRelease(&auth_props);
        return false;
    }
    
    // ssid
    if (ssid_data != NULL) {
        if (EAPOLClientProfileSetWLANSSIDAndSecurityType(profile, ssid_data, security_type) == false) {
            my_CFRelease(&security_type);
            my_CFRelease(&auth_props);
            return false;
        }
    } else if (domain_name != NULL) {
        if (EAPOLClientProfileSetWLANDomain(profile, domain_name) == FALSE) {
            my_CFRelease(&security_type);
            my_CFRelease(&auth_props);
            return false;
        }
    }
    
    if (EAPOLClientConfigurationSave(cfg) == false) {
        my_CFRelease(&security_type);
        my_CFRelease(&auth_props);
        return false;
    }

    my_CFRelease(&ssid_data);
    my_CFRelease(&domain_name);
    my_CFRelease(&auth_props);
    return true;
}

@end


@implementation Eap8021x (EapRemoveProfile)

+ (BOOL)removeProfileWithSSID:(NSString *)ssid {
    if (ssid == nil || ssid.length == 0) {
        return false;
    }
    EAPOLClientConfigurationRef cfg = [self openConfiguration:true];
    if (cfg == nil) {
        return false;
    }
    EAPOLClientProfileRef profile = EAPOLClientConfigurationGetProfileWithWLANSSID(cfg, (__bridge CFDataRef)[ssid dataUsingEncoding:NSUTF8StringEncoding]);
    return [self removeProfileRef:profile cfg:cfg];
}

+ (BOOL)removeProfileWithId:(NSString *)profileId {
    if (profileId == nil) {
        return false;
    }
    EAPOLClientConfigurationRef cfg = [self openConfiguration:true];
    if (cfg == nil) {
        return false;
    }
    EAPOLClientProfileRef profileRef = EAPOLClientConfigurationGetProfileWithID(cfg, (__bridge CFStringRef)profileId);
    return [self removeProfileRef:profileRef cfg:cfg];
}

+ (BOOL)removeProfile:(Eap8021xProfile *)eap8021xProfile {
    NSString *profileID = eap8021xProfile.profileId;
    return [self removeProfileWithId:profileID];
}

+ (BOOL)removeProfileRef:(EAPOLClientProfileRef)profile cfg:(EAPOLClientConfigurationRef)cfg {
    if (profile == nil) {
        return false;
    }
    if (EAPOLClientConfigurationRemoveProfile(cfg, profile) == false) {
        return false;
    }
    if (EAPOLClientConfigurationSave(cfg) == false) {
        return false;
    }
    return true;
}

@end
