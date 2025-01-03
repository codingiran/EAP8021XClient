#
# Be sure to run `pod lib lint EAP8021XClient.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'EAP8021XClient'
  s.version          = '0.2.0'
  s.summary          = 'A short description of EAP8021XClient.'
  
  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC
                       
  s.homepage         = 'https://github.com/codingiran/EAP8021XClient'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'CodingIran' => 'codingiran@gmail.com' }
  s.source           = { :git => 'https://github.com/codingiran/EAP8021XClient.git', :tag => s.version.to_s }
  s.cocoapods_version = '>= 1.13.0'

  s.ios.deployment_target = '13.0'
  s.ios.frameworks = 'Foundation', 'UIKit', 'SystemConfiguration', 'NetworkExtension', 'Security', 'Network'
  s.ios.source_files = 'Sources/EAP8021XClient/**'
  
  s.osx.deployment_target = '10.15'
  s.osx.xcconfig = {'FRAMEWORK_SEARCH_PATHS' => '/System/Library/PrivateFrameworks'}
  s.osx.frameworks = 'Foundation', 'AppKit', 'SystemConfiguration', 'EAP8021X', 'Security', 'CoreWLAN', 'Network'
  s.osx.source_files = 'Sources/EAP8021XClient/**/*', 'Sources/EAP8021XClientObjc/**/*'
  s.osx.public_header_files = 'Sources/EAP8021XClientObjc/include/*.h'
  
  s.resource_bundles = {
    'EAP8021XClient' => ['Sources/Resources/PrivacyInfo.xcprivacy']
  }
  
  s.swift_versions = ['5']

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
