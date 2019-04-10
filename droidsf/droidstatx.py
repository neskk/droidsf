# Original source code developed by @clviper
# https://github.com/clviper/droidstatx

import hashlib
import logging
import os
import re
import time
import xml.etree.ElementTree as ET

import droidsf.utils
from .subprocess import Subprocess, SubprocessShell

from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk, dvm
from androguard.misc import AnalyzeAPK

from droidsf.intent_filter import IntentFilter
from droidsf.smali_checks import SmaliChecks

from elftools.elf.elffile import ELFFile
from io import BytesIO
# from zipfile import ZipFile
import gzip
# import string

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

    def __init__(self, args):
        self.cwd = os.path.dirname(os.path.realpath(__file__))
        self.sha256 = droidsf.utils.sha256_checksum(args.apk_file)

        log.info("Parsing APK: %s", args.apk_file)
        self.apk = apk.APK(args.apk_file)
        self.output_name = (self.apk.get_package() + "_" +
                            self.apk.get_androidversion_code())
        self.output_path = os.path.join(args.output_path, self.output_name)

        log.info("Baksmaling DEX files")
        self.bakmali(args)
        self.smaliChecks = SmaliChecks(args, self.output_name)

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
        log.info("Extracting Files")
        self.extractFiles(args)

        self.export_analysis(args.output_path)

    def export_analysis(self, output_path):
        data = self.get_analysis()
        content = []
        for elem in sorted(data.items()):
            content.append(elem[0] + ": " + str(elem[1]))
        data = self.smaliChecks.get_analysis()
        for elem in sorted(data.items()):
            content.append(elem[0] + ": " + str(elem[1]))

        filename = self.output_name + ".txt"
        droidsf.utils.export_file(output_path, filename, content)
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
        if self.app_xml.get(NS_ANDROID + "networkSecurityConfig") is not None:
            self.networkSecurityConfig = True
            self.parseNetworkSecurityConfigFile()

    def parseNetworkSecurityConfigFile(self):
        path = os.path.join(self.output_path, "/res/xml/network_security_config.xml")
        tree = ET.parse(path)
        root = tree.getroot()
        for child in root:
            if child.tag == "base-config":
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
                log.info(domainConfig)
            if child.tag == "domain-config":
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
                log.info(domainConfig)

    # Create the list of permissions used by the package
    def extractPermissions(self):
        for permission in self.apk.get_permissions():
            self.permissions.append(str(permission))

    def extractCertificate(self):
        self.certificate = self.apk.get_signature_name()

    # Check for the presence of a SECRET_CODE in the object and add it to a global list of objects with SECRET_CODEs.
    def checkForSecretCodes(self, object):
        intentFilters = object.findall("intent-filter")
        for intentFilter in intentFilters:
            if len(intentFilter.findall("data")) > 0:
                datas = intentFilter.findall("data")
                for data in datas:
                    if data.get(NS_ANDROID + "scheme") == "android_secret_code":
                        self.secretCodes.append(data.get(NS_ANDROID + "host"))

    # Create a global list of activities with the excludeFromRecentes attribute
    def extractActivitiesWithExcludeFromRecents(self):
        for activity in self.app_xml.findall("activity"):
            if activity.get(NS_ANDROID + "excludeFromRecents") == 'true':
                self.activitiesWithExcludeFromRecents.append(activity.get(NS_ANDROID + "name"))

    # Create a global list of activities that do not have the FLAG_SECURE or the excludeFromRecents attribute set.
    def extractActivitiesWithoutSecureFlag(self):
        activitiesWithoutSecureFlag = []
        for activity in self.apk.get_activities():
            if self.smaliChecks.doesActivityHasFlagSecure(activity) is False and activity not in self.activitiesWithExcludeFromRecents:
                try:
                    activity.encode("ascii")
                except UnicodeEncodeError as e:
                    activity = activity.encode('ascii', 'xmlcharrefreplace')
                self.activitiesWithoutFlagSecure.append(activity)

    # Return the ProtectionLevel of a particular Permission
    def determinePermissionProtectionLevel(self, targetPermission):
        for permission in self.manifest_xml.findall("permission"):
            if permission.get(NS_ANDROID + "name") == targetPermission:
                print(permission.get(NS_ANDROID + "protectionLevel"))
        return ""

    # Add the extracted permission of a particular component to a global list indexed by the component name.
    def extractComponentPermission(self, component):
        if component.get(NS_ANDROID + "permission") is not None:
            self.componentPermissionList[component.get(NS_ANDROID + "name")] = component.get(NS_ANDROID + "permission")

    # Create a global list with that particular object intent-filters indexed to the component name.
    def extractIntentFilters(self, filters, component):
        filterList = []
        name = component.get(NS_ANDROID + "name")
        log.debug("Extracting Intent Filters from: %s", name)
        filters = component.findall("intent-filter")
        for filter in filters:
            intentFilter = IntentFilter()
            for action in filter.findall("action"):
                intentFilter.addAction(action.get(NS_ANDROID + "name"))
            for category in filter.findall("category"):
                intentFilter.addCategory(category.get(NS_ANDROID + "name"))
            for data in filter.findall("data"):
                if data.get(NS_ANDROID + "scheme") is not None:
                    intentFilter.addData("scheme:" + data.get(NS_ANDROID + "scheme"))
                if data.get(NS_ANDROID + "host") is not None:
                    intentFilter.addData("host:" + data.get(NS_ANDROID + "host"))
                if data.get(NS_ANDROID + "port") is not None:
                    intentFilter.addData("port:" + data.get(NS_ANDROID + "port"))
                if data.get(NS_ANDROID + "path") is not None:
                    intentFilter.addData("path:" + data.get(NS_ANDROID + "path"))
                if data.get(NS_ANDROID + "pathPattern") is not None:
                    intentFilter.addData("pathPattern:" + data.get(NS_ANDROID + "pathPattern"))
                if data.get(NS_ANDROID + "pathPrefix") is not None:
                    intentFilter.addData("pathPrefix:" + data.get(NS_ANDROID + "pathPrefix"))
                if data.get(NS_ANDROID + "mimeType") is not None:
                    intentFilter.addData("mimeType:" + data.get(NS_ANDROID + "mimeType"))
            filterList.append(intentFilter)

        self.intentFilterList[name] = filterList

    # Determine exported Activities taking into account the existence of exported attribute or the presence of intent-filters and also check for presence of secretCode and if vulnerable to Fragment Injection
    # Check if any of the activities (exported or not) have any SECRET_CODE configured.
    def extractExportedActivities(self):
        for activity in self.app_xml.findall("activity"):
            activityName = activity.get(NS_ANDROID + "name")
            self.checkForSecretCodes(activity)
            if len(activity.findall("intent-filter")) > 0:
                filters = activity.findall("intent-filter")
                self.extractIntentFilters(filters, activity)

            if activity.get(NS_ANDROID + "exported") == 'true':
                self.extractComponentPermission(activity)
                if self.smaliChecks.doesActivityExtendsPreferenceActivity(activityName) is True:
                    if self.smaliChecks.doesPreferenceActivityHasValidFragmentCheck(activityName) is True:
                        try:
                            activityName.encode("ascii")
                        except UnicodeEncodeError as e:
                            activityName = activityName.encode('ascii', 'xmlcharrefreplace')
                        self.activitiesExtendPreferencesWithValidate.append(activityName)
                    else:
                        try:
                            activityName.encode("ascii")
                        except UnicodeEncodeError as e:
                            activityName = activityName.encode('ascii', 'xmlcharrefreplace')
                        self.activitiesExtendPreferencesWithoutValidateValidate.append(activityName)
                self.exportedActivities.append(activityName)
                if "com.outsystems.android" in activityName:
                    self.isAppOutsystems = True
            elif activity.get(NS_ANDROID + "exported") != 'false':
                if len(activity.findall("intent-filter")) > 0:
                    self.extractIntentFilters(filters, activity)
                    self.extractComponentPermission(activity)
                    self.exportedActivities.append(activityName)
                    if self.smaliChecks.doesActivityExtendsPreferenceActivity(activityName) is True:
                        if self.smaliChecks.doesPreferenceActivityHasValidFragmentCheck(activityName) is True:
                            try:
                                activityName.encode("ascii")
                            except UnicodeEncodeError as e:
                                activityName = activityName.encode('ascii', 'xmlcharrefreplace')
                            self.activitiesExtendPreferencesWithValidate.append(activityName)
                        else:
                            try:
                                activityName.encode("ascii")
                            except UnicodeEncodeError as e:
                                activityName = activityName.encode('ascii', 'xmlcharrefreplace')
                            self.activitiesExtendPreferencesWithoutValidate.append(activityName)
                    if "com.outsystems.android" in activityName:
                        self.isAppOutsystems = True

    # Determine exported Broadcast Receivers taking into account the existence of exported attribute or the presence of intent-filters
    def extractExportedReceivers(self):
        for receiver in self.app_xml.findall("receiver"):
            receiverName = receiver.get(NS_ANDROID + "name")
            self.checkForSecretCodes(receiver)
            if receiver.get(NS_ANDROID + "exported") == 'true':
                if len(receiver.findall("intent-filter")) > 0:
                    filters = receiver.findall("intent-filter")
                    self.extractIntentFilters(filters, receiver)
                    self.extractComponentPermission(receiver)
                self.exportedReceivers.append(receiverName)
            elif receiver.get(NS_ANDROID + "exported") != 'false':
                if len(receiver.findall("intent-filter")) > 0:
                    filters = receiver.findall("intent-filter")
                    self.extractIntentFilters(filters, receiver)
                    self.extractComponentPermission(receiver)
                    self.exportedReceivers.append(receiverName)

    # Determine exported Content Providers taking into account the existence of exported attribute or without the attributes, under API 16 they are exported by default
    def extractExportedProviders(self):
        for provider in self.app_xml.findall("provider"):
            providerName = provider.get(NS_ANDROID + "name")
            self.checkForSecretCodes(provider)
            if provider.get(NS_ANDROID + "exported") == 'true':
                self.exportedProviders.append(providerName)
                self.smaliChecks.determineContentProviderSQLi(providerName)
                self.smaliChecks.determineContentProviderPathTraversal(providerName)
            elif provider.get(NS_ANDROID + "exported") != 'false':
                if self.minSDKVersion <= 16:
                    self.extractComponentPermission(provider)
                    self.smaliChecks.determineContentProviderSQLi(providerName)
                    self.smaliChecks.determineContentProviderPathTraversal(providerName)
                    self.exportedProviders.append(providerName + " * In devices <= API 16 (Jelly Bean 4.1.x)")

    # Determine exported Services taking into account the existence of exported attribute or the presence of intent-filters
    def extractExportedServices(self):
        for service in self.app_xml.findall("service"):
            serviceName = service.get(NS_ANDROID + "name")
            self.checkForSecretCodes(service)
            if service.get(NS_ANDROID + "exported") == 'true':
                if len(service.findall("intent-filter")) > 0:
                    filters = service.findall("intent-filter")
                    self.extractComponentPermission(service)
                    self.extractIntentFilters(filters, service)
                self.exportedServices.append(serviceName)
            elif service.get(NS_ANDROID + "exported") != 'false':
                if len(service.findall("intent-filter")) > 0:
                    filters = service.findall("intent-filter")
                    self.extractIntentFilters(filters, service)
                    self.extractComponentPermission(service)
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
    def extractFiles(self, args):
        files = self.apk.get_files()
        try:
            for f in files:
                if self.isInExclusions(f, args.file_exclusions):
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

    # Run apktool on the package with the options
    # d : Decompile
    # -b : Don't write out debug info
    # -f : Force rewrite
    # -o : Output folder
    def bakmali(self, args):
        apktool_jar = None
        for root, dirs, files in os.walk(args.download_path):
            for name in files:
                if "apktool" in name:
                    apktool_jar = name
                    break

        if not apktool_jar:
            log.error("Unable to find Apktool in workspace.")
            return False

        if os.path.isfile(os.path.join(self.output_path, ".droidsf")):
            log.debug("Skipped Baksmali, found previous output.")
            return True

        apktool_path = os.path.join(args.download_path, apktool_jar)
        cmd = Subprocess(["java", "-Xms64m", "-Xmx1024m", "-jar", apktool_path, "d", "-b", "-f", "--frame-path", "/tmp/", args.apk_file, "-o", self.output_path])

        if not cmd.success:
            return False

        date = time.strftime("%Y%m%d_%H%M%S")
        droidsf.utils.export_file(self.output_path, ".droidsf", date)
        return True

    def unbundleXamarinDlls(self, lib_path):
        export_path = "xamarin_" + lib_path.split(os.sep)[1]
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
