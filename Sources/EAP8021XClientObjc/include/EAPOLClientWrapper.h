//
//  EAPOLClientWrapper.h
//  wifi_connect
//
//  Created by CodingIran on 2024/12/31.
//

#import <Foundation/Foundation.h>
#import "EAP8021xProfile.h"

NS_ASSUME_NONNULL_BEGIN

@interface EAPOLClientWrapper : NSObject

/// Get profile with SSID 
/// - Parameters:
///   - ssid: SSID
/// - Returns: EAP8021xProfile
+ (nullable EAP8021xProfile *)profileWithSSID:(nullable NSString *)ssid;

/// List profiles
/// - Returns: NSArray<EAP8021xProfile *>
+ (nullable NSArray<EAP8021xProfile *> *)listProfiles;

@end

@interface EAPOLClientWrapper (EAPAddProfile)

/// Create profile method
/// - Parameters:
///   - ssid: SSID
///   - acceptEAPTypes: Accept EAP types
///   - userDefinedName: User defined name
///   - domainName: Domain name
///   - securityType: Security type
///   - outerIdentity: Outer identity
///   - ttlSInnerAuthentication: Inner authentication type
///   - trustedServerName: Trusted server name
///   - trustedCertificate: Trusted certificate
+ (BOOL)createProfileWithSSID:(nullable NSString *)ssid
               acceptEAPTypes:(nullable NSArray<NSNumber *> *)acceptEAPTypes
              userDefinedName:(nullable NSString *)userDefinedName
                   domainName:(nullable NSString *)domainName
                 securityType:(EAP8021xSecurityType)securityType
                outerIdentity:(nullable NSString *)outerIdentity
      ttlSInnerAuthentication:(EAP8021TTLSInnerAuthType)ttlSInnerAuthentication
            trustedServerName:(nullable NSArray<NSString *> *)trustedServerName
           trustedCertificate:(nullable NSArray<NSData *> *)trustedCertificate;

+ (BOOL)createProfileWithEAP8021xProfile:(EAP8021xProfile *)eap8021xProfile;

@end

@interface EAPOLClientWrapper (EAPRemoveProfile)

/// Remove profile with SSID
/// - Parameters:
///   - ssid: SSID
/// - Returns: BOOL
+ (BOOL)removeProfileWithSSID:(NSString *)ssid;

/// Remove profile with ID
/// - Parameters:
///   - profileId: Profile ID
/// - Returns: BOOL
+ (BOOL)removeProfileWithId:(NSString *)profileId;

/// Remove profile
/// - Parameters:
///   - eap8021xProfile: EAP8021x profile
/// - Returns: BOOL
+ (BOOL)removeProfile:(EAP8021xProfile *)eap8021xProfile;

@end

@interface EAPOLClientWrapper (EAPSecTrustedApplicationGroup)

/// Wrapper for SecTrustedApplicationCreateApplicationGroup (Private API)
/// - Parameters:
///   - groupName: Group name
///   - anchor: Anchor
///   - app: App
/// - Returns: OSStatus
+ (OSStatus)secTrustedApplicationCreateApplicationGroup:(nullable const char *)groupName
                                                 anchor:(nullable SecCertificateRef)anchor
                                                    app:(SecTrustedApplicationRef * __nonnull CF_RETURNS_RETAINED)app;

@end

NS_ASSUME_NONNULL_END
