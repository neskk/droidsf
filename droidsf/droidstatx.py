# Original source code developed by @clviper
# https://github.com/clviper/droidstatx

import gzip
import hashlib
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from io import BytesIO

from elftools.elf.elffile import ELFFile

import droidsf.utils
from droidsf.smali_checks import SmaliChecks

log = logging.getLogger(__name__)

NS_ANDROID_URI = "http://schemas.android.com/apk/res/android"
NS_ANDROID = "{http://schemas.android.com/apk/res/android}"

ANDROID_CODENAMES = {
    "3": "Cupcake 1.5",
    "4": "Donut 1.6",
    "5": "Eclair 2.0",
    "6": "Eclair 2.0.1",
    "7": "Eclair 2.1",
    "8": "Froyo 2.2.x",
    "9": "Gingerbread 2.3 - 2.3.2",
    "10": "Gingerbread 2.3.3 - 2.3.7",
    "11": "Honeycomb 3.0",
    "12": "Honeycomb 3.1",
    "13": "Honeycomb 3.2.x",
    "14": "Ice Cream Sandswich 4.0.1 - 4.0.2",
    "15": "Ice Cream Sandswich 4.0.3 - 4.0.4",
    "16": "Jelly Bean 4.1.x",
    "17": "Jelly Bean 4.2.x",
    "18": "Jelly Bean 4.3.x",
    "19": "KitKat 4.4 - 4.4.4",
    "21": "Lolipop 5.0",
    "22": "Lolipop 5.1",
    "23": "Marshmallow 6.0",
    "24": "Nougat 7.0",
    "25": "Nougat 7.1",
    "26": "Oreo 8.0",
    "27": "Oreo 8.1.0",
    "28": "P ",
    "29": "Q"
}

# https://android.jlelse.eu/permission-protection-levels-969c9d0a7ebc
# https://developer.android.com/guide/topics/manifest/permission-element
# 0 - normal | 1 - dangerous | 2 - signature
ANDROID_PERMISSION_PROTECTION_LEVELS = {
    0: "Normal",
    1: "Dangerous",
    2: "Signature"
}

class DroidStatX:
    a = ""
    d = ""
    dx = ""
    xml = ""
    manifest_xml = {}
    app_xml = {}
    exportedActivities = []
    intentFilterList = {}
    componentPermissionList = {}
    activitiesWithExcludeFromRecents = []
    activitiesExtendPreferencesWithValidate = []
    activitiesExtendPreferencesWithoutValidate = []
    activitiesWithoutFlagSecure = []
    exportedReceivers = []
    exportedProviders = []
    exportedServices = []
    permissions = []
    secretCodes = []
    libs = []
    assemblies = []
    assets = []
    cordova = []
    rawResources = []
    dexFiles = []
    otherFiles = []
    cordovaPlugins = []
    networkSecurityConfigDomains = []
    isAppXamarin = False
    xamarinMKBundled = False
    xamarinBundledFile = ""
    isAppCordova = False
    isAppOutsystems = False
    networkSecurityConfig = False
    minSDKVersion = ""
    targetSDKVersion = ""
    versionCode = ""
    versionName = ""
    sha256 = ""
    packageName = ""
    debuggable = False
    allowBackup = False
    certificate = ""

    baksmaliPaths = []
    smaliChecks = None

    def __init__(self, args, apk):
        self.args = args
        self.apk = apk.apk  # androguard.core.bytecodes.apk
        self.sha256 = apk.sha256
        self.output_name = apk.output_name
        self.output_path = apk.output_path

        self.smaliChecks = SmaliChecks(self.args, apk)
        self.performAnalysis()

    def performAnalysis(self):
        log.info("Analysing manifest.xml")
        self.manifest_xml = self.apk.get_android_manifest_axml().get_xml_obj()
        self.app_xml = self.manifest_xml.findall("application")[0]

        log.info("Extracting Activities")
        self.extractActivitiesWithExcludeFromRecents()
        self.extractActivitiesWithoutSecureFlag()
        log.info("Extracting Package Properties")
        self.extractPackageProperties()
        log.info("Extracting Exported Components")
        self.extractExportedComponents()
        log.info("Extracting Permissions")
        self.extractPermissions()
        self.extractPermissionProtectionLevels()
        log.info("Extracting Files")
        self.extractFiles()

        self.export_analysis()

    def export_analysis(self):
        data = self.get_analysis()
        content = []
        for elem in sorted(data.items()):
            content.append(elem[0] + ": " + str(elem[1]))
        data = self.smaliChecks.get_analysis()
        for elem in sorted(data.items()):
            content.append(elem[0] + ": " + str(elem[1]))

        filename = self.output_name + ".txt"
        droidsf.utils.export_file(self.args.output_path, filename, content)
        log.info("Exported analysis to: %s", filename)

    # Return the Android Code Name for the particular Api Level.
    def getCodeName(self, apiLevel):
        return ANDROID_CODENAMES[apiLevel]

    # Extract package properties such as the minSDKVersion, PackageName, VersionName, VersionCode, isDebuggable, allowBackup
    def extractPackageProperties(self):
        usesSDK = self.manifest_xml.findall("uses-sdk")
        self.minSDKVersion = self.apk.get_min_sdk_version()
        self.targetSDKVersion = self.apk.get_target_sdk_version()
        self.packageName = self.apk.get_package()
        self.versionName = self.apk.get_androidversion_name()
        self.versionCode = self.apk.get_androidversion_code()
        if self.app_xml.get(NS_ANDROID + "debuggable") == 'true':
            self.debuggable = True
        if self.app_xml.get(NS_ANDROID + "allowBackup") == 'true':
            self.allowBackup = True
        elif self.app_xml.get(NS_ANDROID + "allowBackup") == 'false':
            self.allowBackup = False
        else:
            self.allowBackup = True

        networkSecurityConfig = self.app_xml.get(NS_ANDROID + "networkSecurityConfig")
        if networkSecurityConfig:
            self.networkSecurityConfig = True
            self.parseNetworkSecurityConfigFiles(networkSecurityConfig)

    def parseNetworkSecurityConfigFiles(self, namespace):
        xml_path = os.path.join(self.output_path, "res/xml")
        config_file = os.path.join(xml_path, "network_security_config.xml")

        xml_files = []
        if os.path.isfile(config_file):
            xml_files.append(config_file)
        elif os.path.isdir(xml_path):
            for root, dirs, files in os.walk(xml_path):
                xml_files = [os.path.join(root, f) for f in files if f.endswith(".xml")]
                # for name in files:
                #     xml_files.append(os.path.join(root, name))

        for file_path in xml_files:
            tree = ET.parse(file_path)
            root = tree.getroot()
            if self.parseNetworkSecurityConfigFile(root):
                log.info("Found network security config (%s) file: %s", namespace, file_path)

    def parseNetworkSecurityConfigFile(self, root):
        foundConfig = False

        for child in root:
            if child.tag == "base-config" or child.tag == "domain-config":
                domainConfig = {
                    'domains': [],
                    'allowClearText': True,
                    'allowUserCA': False,
                    'pinning': False,
                    'pinningExpiration': ''
                }
                if 'cleartextTrafficPermitted' in child.attrib:
                    if child.attrib['cleartextTrafficPermitted'] == "false":
                        domainConfig['allowClearText'] = False
                for sub in child:
                    if sub.tag == "domain":
                        domainConfig['domains'].append(sub.text)
                    if sub.tag == "trust-anchors":
                        for certificates in sub:
                            if certificates.attrib['src'] == "user":
                                domainConfig['allowUserCA'] = True
                    if sub.tag == "pin-set":
                        domainConfig['pinning'] = True
                        if 'expiration' in sub.attrib:
                            domainConfig['pinningExpiration'] = sub.attrib['expiration']
                self.networkSecurityConfigDomains.append(domainConfig)
                foundConfig = True

        return foundConfig

    # Create the list of permissions used by the package
    def extractPermissions(self):
        for permission in self.apk.get_permissions():
            log.warning("Application requires permission: %s", permission)
            self.permissions.append(permission)

    def extractPermissionProtectionLevels(self):
        self.permissionProtectionLevels = {}
        for permission in self.manifest_xml.findall("permission"):
            name = permission.get(NS_ANDROID + "name")
            level = int(permission.get(NS_ANDROID + "protectionLevel"), 16)
            level_name = ANDROID_PERMISSION_PROTECTION_LEVELS[level]

            log.debug("Found Permission: %s - %s", name, level_name)
            self.permissionProtectionLevels[name] = level_name

    def extractCertificate(self):
        self.certificate = self.apk.get_signature_name()

    # Create a global list of activities with the excludeFromRecents attribute
    # XXX: Checked with sweatcoin
    def extractActivitiesWithExcludeFromRecents(self):
        for activity in self.app_xml.findall("activity"):
            if activity.get(NS_ANDROID + "excludeFromRecents") == 'true':
                self.activitiesWithExcludeFromRecents.append(activity.get(NS_ANDROID + "name"))

    # Create a global list of activities that do not have the FLAG_SECURE or the excludeFromRecents attribute set.
    # XXX: Checked with sweatcoin / de.zertapps.dvhma.featherweight
    def extractActivitiesWithoutSecureFlag(self):
        activitiesWithoutSecureFlag = []
        # for activity in self.apk.get_activities():
        for activity in self.app_xml.findall("activity"):
            activityName = activity.get(NS_ANDROID + "name")

            # if activityName.startswith("."):
            #     activityName = self.apk.get_package() + activityName

            if self.smaliChecks.doesActivityHasFlagSecure(activityName):
                log.warning("Activity %s sets FLAG_SECURE.", activityName)
            elif activityName not in self.activitiesWithExcludeFromRecents:
                # try:
                #     activity.encode("ascii")
                # except UnicodeEncodeError as e:
                #     activity = activity.encode('ascii', 'xmlcharrefreplace')
                self.activitiesWithoutFlagSecure.append(activityName)
            else:
                log.warning("Activity %s is on ExcludeFromRecents", activityName)

    # Add the extracted permission of a particular component to a global list indexed by the component name.
    def extractComponentPermission(self, component):
        name = component.get(NS_ANDROID + "name")
        permission = component.get(NS_ANDROID + "permission")

        if permission:
            self.componentPermissionList[name] = permission

    # https://developer.android.com/guide/components/intents-filters
    # Create a global list with that particular object intent-filters indexed to the component name.
    def extractIntentFilters(self, component):
        name = component.get(NS_ANDROID + "name")
        items = component.findall("intent-filter")

        if not items:
            # log.debug("Component %s has no Intent Filters.", name)
            return

        filterList = []
        for item in items:
            intent_filter = {
                "action": [],
                "category": [],
                "data": []
            }
            for action in item.findall("action"):
                intent_filter["action"].append(action.get(NS_ANDROID + "name"))
            for category in item.findall("category"):
                intent_filter["category"].append(category.get(NS_ANDROID + "name"))
            for data in item.findall("data"):
                scheme = data.get(NS_ANDROID + "scheme")
                host = data.get(NS_ANDROID + "host")
                port = data.get(NS_ANDROID + "port")
                path = data.get(NS_ANDROID + "path")
                pathPattern = data.get(NS_ANDROID + "pathPattern")
                pathPrefix = data.get(NS_ANDROID + "pathPrefix")
                mimeType = data.get(NS_ANDROID + "mimeType")
                if scheme:
                    intent_filter["data"].append("scheme:" + scheme)
                    # Check presence of a SECRET_CODE
                    if scheme == "android_secret_code":
                        self.secretCodes.append(name)
                        intent_filter["data"].append("android_secret_code")
                if host:
                    intent_filter["data"].append("host:" + host)
                if port:
                    intent_filter["data"].append("port:" + port)
                if path:
                    intent_filter["data"].append("path:" + path)
                if pathPattern:
                    intent_filter["data"].append("pathPattern:" + pathPattern)
                if pathPrefix:
                    intent_filter["data"].append("pathPrefix:" + pathPrefix)
                if mimeType:
                    intent_filter["data"].append("mimeType:" + mimeType)

            filterList.append(intent_filter)

        self.intentFilterList[name] = filterList

    # Determine exported Activities taking into account the existence of exported attribute or the presence of intent-filters and check if vulnerable to Fragment Injection
    def extractExportedActivities(self):
        for activity in self.app_xml.findall("activity"):
            activityName = activity.get(NS_ANDROID + "name")

            # Extract Permission
            self.extractComponentPermission(activity)

            # Extract Intent Filters
            self.extractIntentFilters(activity)

            # Detect OutSystems applications
            if "com.outsystems.android" in activityName:
                    self.isAppOutsystems = True

            if self.smaliChecks.doesPreferenceActivityHasValidFragmentCheck(activityName):
                self.activitiesExtendPreferencesWithValidate.append(activityName)
            else:
                self.activitiesExtendPreferencesWithoutValidate.append(activityName)

            exported = activity.get(NS_ANDROID + "exported")  # 'true' / 'false' / None
            if exported == "true":
                log.debug("Exported activity %s: found 'exported' attribute.", activityName)
                self.exportedActivities.append(activityName)
            elif exported != "false" and activityName in self.intentFilterList:
                log.debug("Exported activity %s: found Intent Filters.", activityName)
                self.exportedActivities.append(activityName)

    # Determine exported Broadcast Receivers taking into account the existence of exported attribute or the presence of intent-filters
    def extractExportedReceivers(self):
        for receiver in self.app_xml.findall("receiver"):
            receiverName = receiver.get(NS_ANDROID + "name")

            # Extract Permission
            self.extractComponentPermission(receiver)

            # Extract Intent Filters
            self.extractIntentFilters(receiver)

            exported = receiver.get(NS_ANDROID + "exported")  # 'true' / 'false' / None
            if exported == "true":
                log.debug("Exported receiver %s: found 'exported' attribute.", receiverName)
                self.exportedReceivers.append(receiverName)
            elif exported != "false" and receiverName in self.intentFilterList:
                log.debug("Exported activity %s: found Intent Filters.", receiverName)
                self.exportedReceivers.append(receiverName)

    # Determine exported Content Providers taking into account the existence of exported attribute or without the attributes, under API 16 they are exported by default
    def extractExportedProviders(self):
        for provider in self.app_xml.findall("provider"):
            providerName = provider.get(NS_ANDROID + "name")

            # Extract Permission
            self.extractComponentPermission(provider)

            # # Hack: some APKs have their manifest with relative provider names
            # if providerName.startswith("."):
            #     providerName = provider.get(NS_ANDROID + "authorities")

            self.smaliChecks.determineContentProviderSQLi(providerName)
            self.smaliChecks.determineContentProviderPathTraversal(providerName)

            exported = provider.get(NS_ANDROID + "exported")  # 'true' / 'false' / None
            if exported == "true":
                log.debug("Exported provider %s: found 'exported' attribute.", providerName)
                self.exportedProviders.append(providerName)
            elif exported != "false" and self.minSDKVersion <= 16:
                log.debug("Exported provider %s: minSDK version <= 16.", providerName)
                self.exportedProviders.append(providerName + " * In devices <= API 16 (Jelly Bean 4.1.x)")

    # Determine exported Services taking into account the existence of exported attribute or the presence of intent-filters
    def extractExportedServices(self):
        for service in self.app_xml.findall("service"):
            serviceName = service.get(NS_ANDROID + "name")

            # Extract Permission
            self.extractComponentPermission(service)

            # Extract Intent Filters
            self.extractIntentFilters(service)

            exported = service.get(NS_ANDROID + "exported")  # 'true' / 'false' / None
            if exported == "true":
                log.debug("Exported service %s: found 'exported' attribute.", serviceName)
                self.exportedServices.append(serviceName)
            elif exported != "false" and serviceName in self.intentFilterList:
                log.debug("Exported service %s: found Intent Filters.", serviceName)
                self.exportedServices.append(serviceName)

    # Run the functions that extract the exported components.
    def extractExportedComponents(self):
        self.extractExportedActivities()
        self.extractExportedReceivers()
        self.extractExportedProviders()
        self.extractExportedServices()

    # Determine if path is in the exclude paths configured in the config file.
    def isInExclusions(self, filename, exclusions):
        for pattern in exclusions:
            if pattern in filename:
                return True
        return False

    # Create a list of files, organized in several types and while doing it, by the existence of certain files, determine if the app is a Cordova or Xamarin app.
    def extractFiles(self):
        files = self.apk.get_files()
        try:
            for f in files:
                if self.isInExclusions(f, self.args.file_exclusions):
                    continue
                try:
                    f.encode("ascii")
                except UnicodeEncodeError as e:
                    f = f.encode('ascii', 'xmlcharrefreplace')
                if "assets/www/" in f:
                    if "assets/www/cordova.js" in f:
                        self.isAppCordova = True
                    if "assets/www/plugins/" in f:
                        beginPos = f.find("/plugins/") + 9
                        endPos = f.find("/", beginPos)
                        item = f[beginPos:endPos]
                        self.cordovaPlugins.append(item) if item not in self.cordovaPlugins else None
                    self.cordova.append(f)
                elif f[0:4] == "lib/":
                    self.libs.append(f)
                    if 'libmonodroid_bundle_app.so' in f:
                        self.isAppXamarin = True
                        self.xamarinMKBundled = True
                        self.xamarinBundledFile = f
                        self.unbundleXamarinDlls(f)
                elif f[0:11] == "assemblies/" in f:
                    self.assemblies.append(f)
                    if 'Xamarin.' in f and self.isAppXamarin is False:
                        self.isAppXamarin = True
                elif "assets/" in f:
                    self.assets.append(f)
                elif "res/raw/" in f:
                    self.rawResources.append(f)
                elif ".dex" in f:
                    self.dexFiles.append(f)
                else:
                    self.otherFiles.append(f)
        except UnicodeDecodeError as e:
            pass

    def unbundleXamarinDlls(self, lib_path):
        export_path = "xamarin_" + lib_path.split("/")[1]
        file_path = os.path.join(self.output_path, lib_path)
        output_path = os.path.join(self.output_path, export_path)
        log.info("Unpacking %s to %s.", lib_path, output_path)
        with open(file_path, "rb") as f:
            data = f.read()
            elffile = ELFFile(f)
            log.debug("Loaded ELF file: %s", lib_path)
            section = elffile.get_section_by_name('.dynsym')

            for symbol in section.iter_symbols():
                if symbol['st_shndx'] != 'SHN_UNDEF' and symbol.name.startswith('assembly_data_'):
                    start_offset = symbol['st_value']
                    end_offset = symbol['st_value'] + symbol['st_size']

                    dll_data = data[start_offset:end_offset]
                    dll_data = gzip.GzipFile(fileobj=BytesIO(dll_data)).read()

                    filename = symbol.name[14:].replace('_dll', '.dll')
                    droidsf.utils.export_file(output_path, filename, dll_data, mode="wb")
                    log.debug("Exported Xamarin DLL: %s", filename)

    # *** GETTERS ***

    def get_analysis(self):
        attrs = [
            "permissions",
            "exportedActivities",
            "exportedReceivers",
            "exportedProviders",
            "exportedServices",
            "packageName",
            "minSDKVersion",
            "targetSDKVersion",
            "versionName",
            "versionCode",
            "sha256",
            "isAppCordova",
            "isAppXamarin",
            "xamarinMKBundled",
            "isAppOutsystems",
            "debuggable",
            "allowBackup",
            "networkSecurityConfig",
            "isMultiDex",
            "assets",
            "cordova",
            "rawResources",
            "libs",
            "otherFiles",
            "assemblies",
            "dexFiles",
            "secretCodes",
            "intentFilterList",
            "networkSecurityConfigDomains",
            "activitiesWithExcludeFromRecents",
            "activitiesWithoutFlagSecure",
            "activitiesExtendPreferencesWithValidate",
            "activitiesExtendPreferencesWithoutValidate",
            "cordovaPlugins"
        ]
        data = {}
        for attr in attrs:
            value = getattr(self, attr)
            if isinstance(value, list):
                try:
                    value = sorted(value)
                except TypeError:
                    pass
            elif callable(value):
                value = value()

            data[attr] = value

        return data

    # Return the permission defined in the particular component.
    # XXX: unused
    def getComponentPermission(self, name):
        try:
            return self.componentPermissionList[name]
        except:
            return ""

    # Return the app permissions global list
    def getPermissions(self):
        return self.permissions

    # Return the exported activities global list
    def getExportedActivities(self):
        return self.exportedActivities

    # Return the the exported broadcast receivers global list
    def getExportedReceivers(self):
        return self.exportedReceivers

    # Return the exported content providers global list
    def getExportedProviders(self):
        return self.exportedProviders

    # Return the exported services global list
    def getExportedServices(self):
        return self.exportedServices

    # Return the app package name
    def getPackageName(self):
        return self.packageName

    # Return the app minSDKVersion
    def getMinSDKVersion(self):
        return self.minSDKVersion

    # Return the app targetSDKVersion
    def getTargetSDKVersion(self):
        return self.targetSDKVersion

    # Return the app versionName
    def getVersionName(self):
        return self.versionName

    # Return the app versionCode
    def getVersionCode(self):
        return self.versionCode

    # Return the APK SHA256
    def getSHA256(self):
        return self.sha256

    def isCordova(self):
        if self.isAppCordova is True:
            return "Yes"
        else:
            return "No"

    def isXamarin(self):
        if self.isAppXamarin is True:
            return "Yes"
        else:
            return "No"

    def isXamarinBundled(self):
        if self.xamarinMKBundled is True:
            return "Yes"
        else:
            return "No"

    def isOutsystems(self):
        if self.isAppOutsystems is True:
            return "Yes"
        else:
            return "No"

    def isDebuggable(self):
        if self.debuggable is True:
            return "Yes"
        else:
            return "No"

    def isBackupEnabled(self):
        if self.allowBackup is True:
            return "Yes"
        else:
            return "No"

    def hasNetworkSecurityConfig(self):
        return self.networkSecurityConfig

    def isMultiDex(self):
        return len(self.dexFiles) > 1

    def getAssets(self):
        return self.assets

    def getCordovaFiles(self):
        return self.cordova

    def getRawResources(self):
        return self.rawResources

    def getLibs(self):
        return self.libs

    def getOtherFiles(self):
        return self.otherFiles

    def getXamarinAssemblies(self):
        return self.assemblies

    def getDexFiles(self):
        return self.dexFiles

    def getSecretCodes(self):
        return self.secretCodes

    def getIntentFiltersList(self):
        return self.intentFilterList

    def getNetworkSecurityConfigDomains(self):
        return self.networkSecurityConfigDomains

    def getActivitiesWithExcludeFromRecents(self):
        return self.activitiesWithExcludeFromRecents

    def getActivitiesWithoutSecureFlag(self):
        return self.activitiesWithoutFlagSecure

    def getActivitiesExtendPreferencesWithValidate(self):
        return self.activitiesExtendPreferencesWithValidate

    def getActivitiesExtendPreferencesWithoutValidate(self):
        return self.activitiesExtendPreferencesWithoutValidate

    def getCordovaPlugins(self):
        return self.cordovaPlugins
