//
//  EAP8021xProfile.h
//  EAP8021XClient
//
//  Created by CodingIran on 2025/1/8.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 EAP Type
 */
typedef NS_ENUM(NSInteger, EAP8021xEAPType) {
    EAP8021xEAPTypeInvalid = 0,
    EAP8021xEAPTypeIdentity = 1,
    EAP8021xEAPTypeNotification = 2,
    EAP8021xEAPTypeNak = 3,
    EAP8021xEAPTypeMD5Challenge = 4,
    EAP8021xEAPTypeOneTimePassword = 5,
    EAP8021xEAPTypeGenericTokenCard = 6,
    EAP8021xEAPTypeTLS = 13,
    EAP8021xEAPTypeCiscoLEAP = 17,
    EAP8021xEAPTypeEAPSIM = 18,
    EAP8021xEAPTypeSRPSHA1 = 19,
    EAP8021xEAPTypeTTLS = 21,
    EAP8021xEAPTypeEAPAKA = 23,
    EAP8021xEAPTypePEAP = 25,
    EAP8021xEAPTypeMSCHAPv2 = 26,
    EAP8021xEAPTypeExtensions = 33,
    EAP8021xEAPTypeEAPFAST = 43,
    EAP8021xEAPTypeEAPAKAPrime = 50
};

/**
 Security type
 */
typedef NS_ENUM(NSInteger, EAP8021xSecurityType) {
    EAP8021xSecurityTypeUnknown = 0,
    EAP8021xSecurityTypeWEP,
    EAP8021xSecurityTypeWPA,
    EAP8021xSecurityTypeWPA2,
    EAP8021xSecurityTypeAny
};

/**
 Inner authentication type
 */
typedef NS_ENUM(NSInteger, EAP8021TTLSInnerAuthType) {
    EAP8021TTLSInnerAuthTypeUnknown = 0,
    EAP8021TTLSInnerAuthTypePAP,
    EAP8021TTLSInnerAuthTypeCHAP,
    EAP8021TTLSInnerAuthTypeMSCHAP,
    EAP8021TTLSInnerAuthTypeMSCHAPv2
};

/**
 EAP8021xProfile: EAP8021x Profile is used to configure EAP8021x settings.
 */
@interface EAP8021xProfile : NSObject

/// Profile ID  
@property (nullable, nonatomic, copy) NSString *profileId;

/// SSID
@property (nullable, nonatomic, copy) NSString *ssid;

/// User defined name
@property (nullable, nonatomic, copy) NSString *userDefinedName;

/// Domain name
@property (nullable, nonatomic, copy) NSString *domainName;

/// Outer identity
@property (nullable, nonatomic, copy) NSString *outerIdentity;

/// Accept EAP types
@property (nullable, nonatomic, copy) NSArray<NSNumber *> *acceptEAPTypes;

/// Security type
@property (nonatomic, assign) EAP8021xSecurityType securityType;

/// Inner authentication type
@property (nonatomic, assign) EAP8021TTLSInnerAuthType ttlsInnerAuthType;

/// Trusted server name
@property (nullable, nonatomic, copy) NSArray<NSString *> *trustedServerName;

/// Trusted certificate
@property (nullable, nonatomic, copy) NSArray<NSData *> *trustedCertificate;

/// Convert EAP8021xEAPType to string
/// - Parameter eapType: EAP8021xEAPType
+ (nullable NSString *)eapTypeToString:(EAP8021xEAPType)eapType;

/// Convert string to EAP8021xSecurityType
/// - Parameter securityType: string
+ (EAP8021xSecurityType)stringToSecurityType:(NSString *)securityType;

/// Convert EAP8021xSecurityType to string
/// - Parameter securityType: EAP8021xSecurityType
+ (nullable NSString *)securityTypeToString:(EAP8021xSecurityType)securityType;

/// Convert string to EAP8021TTLSInnerAuthType
/// - Parameter authType: string
+ (EAP8021TTLSInnerAuthType)stringToTTLSInnerAuthType:(NSString *)authType;

/// Convert EAP8021TTLSInnerAuthType to string
/// - Parameter authType: EAP8021TTLSInnerAuthType
+ (nullable NSString *)ttlsInnerAuthTypeToString:(EAP8021TTLSInnerAuthType)authType;

@end

NS_ASSUME_NONNULL_END
