//
//  Eap8021x.h
//  wifi_connect
//
//  Created by CodingIran on 2024/12/31.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, Eap8021xEAPType) {
    Eap8021xEAPTypeInvalid = 0,
    Eap8021xEAPTypeIdentity = 1,
    Eap8021xEAPTypeNotification = 2,
    Eap8021xEAPTypeNak = 3,
    Eap8021xEAPTypeMD5Challenge = 4,
    Eap8021xEAPTypeOneTimePassword = 5,
    Eap8021xEAPTypeGenericTokenCard = 6,
    Eap8021xEAPTypeTLS = 13,
    Eap8021xEAPTypeCiscoLEAP = 17,
    Eap8021xEAPTypeEAPSIM = 18,
    Eap8021xEAPTypeSRPSHA1 = 19,
    Eap8021xEAPTypeTTLS = 21,
    Eap8021xEAPTypeEAPAKA = 23,
    Eap8021xEAPTypePEAP = 25,
    Eap8021xEAPTypeMSCHAPv2 = 26,
    Eap8021xEAPTypeExtensions = 33,
    Eap8021xEAPTypeEAPFAST = 43,
    Eap8021xEAPTypeEAPAKAPrime = 50
};

typedef NS_ENUM(NSInteger, Eap8021xSecurityType) {
    Eap8021xSecurityTypeUnknown = 0,
    Eap8021xSecurityTypeWEP,
    Eap8021xSecurityTypeWPA,
    Eap8021xSecurityTypeWPA2,
    Eap8021xSecurityTypeAny
};

typedef NS_ENUM(NSInteger, Eap8021TTLSInnerAuthType) {
    Eap8021TTLSInnerAuthTypeUnknown = 0,
    Eap8021TTLSInnerAuthTypePAP,
    Eap8021TTLSInnerAuthTypeCHAP,
    Eap8021TTLSInnerAuthTypeMSCHAP,
    Eap8021TTLSInnerAuthTypeMSCHAPv2
};

@interface Eap8021xProfile : NSObject

@property (nullable, nonatomic, copy) NSString *profileId;
@property (nullable, nonatomic, copy) NSString *ssid;
@property (nullable, nonatomic, copy) NSString *userDefinedName;
@property (nullable, nonatomic, copy) NSString *domainName;
@property (nullable, nonatomic, copy) NSString *outerIdentity;
@property (nullable, nonatomic, copy) NSArray<NSNumber *> *acceptEAPTypes;
@property (nonatomic, assign) Eap8021xSecurityType securityType;
@property (nonatomic, assign) Eap8021TTLSInnerAuthType ttlsInnerAuthType;
@property (nullable, nonatomic, copy) NSArray<NSString *> *trustedServerName;
@property (nullable, nonatomic, copy) NSArray<NSData *> *trustedCertificate;

+ (nullable NSString *)eapTypeToString:(Eap8021xEAPType)eapType;

+ (Eap8021xSecurityType)stringToSecurityType:(NSString *)securityType;

+ (nullable NSString *)securityTypeToString:(Eap8021xSecurityType)securityType;

+ (Eap8021TTLSInnerAuthType)stringToTTLSInnerAuthType:(NSString *)authType;

+ (nullable NSString *)ttlsInnerAuthTypeToString:(Eap8021TTLSInnerAuthType)authType;

@end

@interface Eap8021x : NSObject

+ (nullable Eap8021xProfile *)profileWithSSID:(nullable NSString *)ssid;

+ (nullable NSArray<Eap8021xProfile *> *)listProfiles;

@end

@interface Eap8021x (EapAddProfile)

+ (BOOL)createProfileWithSSID:(nullable NSString *)ssid
               acceptEAPTypes:(nullable NSArray<NSNumber *> *)acceptEAPTypes
              userDefinedName:(nullable NSString *)userDefinedName
                   domainName:(nullable NSString *)domainName
                 securityType:(Eap8021xSecurityType)securityType
                outerIdentity:(nullable NSString *)outerIdentity
      ttlSInnerAuthentication:(Eap8021TTLSInnerAuthType)ttlSInnerAuthentication
            trustedServerName:(nullable NSArray<NSString *> *)trustedServerName
           trustedCertificate:(nullable NSArray<NSData *> *)trustedCertificate;

+ (BOOL)createProfileWithEap8021xProfile:(Eap8021xProfile *)eap8021xProfile;

@end

@interface Eap8021x (EapRemoveProfile)

+ (BOOL)removeProfileWithSSID:(NSString *)ssid;

+ (BOOL)removeProfileWithId:(NSString *)profileId;

+ (BOOL)removeProfile:(Eap8021xProfile *)eap8021xProfile;

@end

NS_ASSUME_NONNULL_END
