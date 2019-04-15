import logging
import os
import re
import mmap
from subprocess import PIPE, Popen
from sys import platform
from timeit import default_timer

import droidsf.utils
from droidsf.grep import Grep

log = logging.getLogger(__name__)

class NotFound(Exception):
    """Object not found in source code"""

class SmaliChecks:

    smaliPaths = []
    activityLocations = {}
    vulnerableTrustManagers = []
    vulnerableWebViewSSLErrorBypass = []
    vulnerableSetHostnameVerifiers = []
    vulnerableHostnameVerifiers = []
    vulnerableSocketsLocations = []
    vulnerableContentProvidersSQLiLocations = []
    vulnerableContentProvidersPathTraversalLocations = []
    dynamicRegisteredBroadcastReceiversLocations = []
    encryptionFunctionsLocation = []
    decryptionFunctionsLocation = []
    undeterminedCryptographicFunctionsLocation = []
    keystoreLocations = []
    webViewLoadUrlUsageLocation = []
    webViewAddJavascriptInterfaceUsageLocation = []
    okHttpCertificatePinningLocation = []
    customCertifificatePinningLocation = []
    AESwithECBLocations = []
    DESLocations = []
    javascriptEnabledWebviews = []
    fileAccessEnabledWebviews = []
    universalAccessFromFileURLEnabledWebviewsLocations = []
    customChecksLocations = {}

    def __init__(self, args, apk):
        self.args = args
        self.apk = apk  # droidsf.apk.APK

        self.dir_exclusions = args.directory_exclusions
        self.file_exclusions = args.file_exclusions

        self.smaliPaths = apk.smali_paths

        # if args.verbose:
        #     self.getMethod = droidsf.utils.timeit(self.getMethod)

        log.info("Analysing smali paths: %s", self.smaliPaths)
        self.checkWebviewSSLErrorBypass()
        self.findWebviewJavascriptInterfaceUsage()
        self.findWeakCryptographicUsage()
        self.checkVulnerableTrustManagers()
        self.checkInsecureHostnameVerifier()
        self.checkVulnerableSockets()
        self.findEncryptionFunctions()
        self.checkVulnerableHostnameVerifiers()
        self.findWebViewLoadUrlUsage()
        self.findPropertyEnabledWebViews()
        self.checkOKHttpCertificatePinning()
        self.checkCustomPinningImplementation()
        self.findKeystoreUsage()
        self.findDynamicRegisteredBroadcastReceivers()
        # self.findPathTraversalContentProvider()
        self.findCustomChecks(args.custom_checks)

    def getFileContent(self, filePath):
        content = droidsf.utils.load_file(filePath)
        return content.strip().replace('    ', '').split('\n')

    def getMethod(self, startPattern, endPattern, filePath):
        start_regex = re.compile(startPattern)
        end_regex = re.compile(endPattern)
        content = droidsf.utils.load_file(filePath)
        inside = False
        res = []
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            if inside:
                res.append(line)
                if re.search(end_regex, line):
                    inside = False
            elif re.search(start_regex, line):
                res.append(line)
                inside = True

        # if not res:
        #     log.info("start: %s | end: %s - found nothing on %s", startPattern, endPattern, filePath)
        # else:
        #     log.debug("start: %s | end: %s - on %s matched %d lines. ", startPattern, endPattern, filePath, len(res))
        # if len(res) < 10:
        #     log.info("\n%s", "\n".join(res))
        return res

    # # https://www.tutorialspoint.com/sed/sed_pattern_range.htm
    # @droidsf.utils.timeit
    # def getMethodCompleteInstructions(self, methodRegEx, filePath):
    #     command = ["sed", "-n", methodRegEx, filePath]
    #     # log.info(" ".join(command))
    #     sed = Popen(command, stdout=PIPE, universal_newlines=True)
    #     out = sed.communicate()[0]
    #     methodContent = out.strip().split('\n')
    #     methodContent = [l.strip() for l in methodContent if l.strip()]

    #     # if not methodContent:
    #     #     log.info("sed search %s empty on %s", methodRegEx, filePath)
    #     # else:
    #     #     log.debug("sed search %s on %s matched %d lines. ", methodRegEx, filePath, len(methodContent))
    #     # if len(methodContent) < 10:
    #     #     log.info("\n%s", "\n".join(methodContent))
    #     return methodContent

    # def getMethodInstructions(self, methodRegEx, filePath):
    #     command = ["sed", "-n", methodRegEx, filePath]
    #     log.info(" ".join(command))
    #     sed = Popen(command, stdout=PIPE, universal_newlines=True)
    #     methodContent = sed.communicate()[0]
    #     try:
    #         match = re.search(r"\.locals \d{1,}([\S\s]*?)\.end method", methodContent)
    #         instructions = str(match.group(1)).strip().replace('    ', '').split('\n')
    #         return instructions
    #     except:
    #         return ""

    # XXX: working
    def isMethodEmpty(self, instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if instructions[i] == '.end method':
                continue
            else:
                if instructions[i] == "return-void":
                    return True
                else:
                    return False

    # XXX: working
    # Check if method returns null value.
    def doesMethodReturnNull(self, method, instruction=""):
        for i in range(len(method) - 1, 0, -1):
            if method[i] == "return-object v0":
                if i - 1 >= 0 and method[i - 1] == "const/4 v0, 0x0":
                    return True
                elif i - 1 >= 0 and method[i - 1] == instruction:
                    if i - 2 >= 0 and method[i - 2] == "const/4 v0, 0x0":
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                continue
        return False

    # XXX: working
    # Check if method returns true
    def doesMethodReturnTrue(self, method):
        maxLen = len(method) - 1
        for i in range(maxLen, 0, -1):
            if method[i] == "return v0":
                if i - 1 >= 0 and method[i - 1] == "const/4 v0, 0x1":
                    return True
                else:
                    return False
            else:
                continue
        return False

    # XXX: Working
    # Find the register that has the target value assigned
    def findRegisterByAssignedValue(self, method, value):
        for instruction in method:
            if "const/" in instruction and value in instruction:
                registerEnd = instruction.find(",")
                registerBegin = instruction.find(" ", 0, registerEnd) + 1
                register = instruction[registerBegin:registerEnd].strip()
                return register

        return None

    # XXX: Working
    # XXX: Checked with com.htbridge.pivaa
    # Find value assigned to register going backwards on method instructions, starting in index
    def findRegisterAssignedValueFromIndexBackwards(self, method, register, index):
        for pointer in range(index, 0, -1):
            instruction = method[pointer]
            if register not in instruction:
                continue
            if "const" in instruction or "sget-object" in instruction:
                valueBegin = instruction.find(",")
                value = instruction[valueBegin + 2:]
                return value

        return None

    # XXX: Working
    # Find registers passed to function in instruction
    def findRegistersPassedToFunction(self, instruction):
        registers = []
        match = re.search(r"{(.*)}", instruction)
        if match:
            registers = match.group(1).strip().replace(' ', '')

            if "range" in instruction:
                registers = registers.split("..")
            else:
                registers = registers.split(",")
        else:
            match = re.findall(r"\D\d", instruction)
            registers = [m.group(0) for m in match]

        return registers

    # XXX: Working
    # Search method instructions for pattern and return its index
    def findInstructionIndex(self, method, pattern):
        indexList = []
        regex = re.compile(pattern)
        for index, instruction in enumerate(method):
            if re.search(regex, instruction):
                indexList.append(index)

        return indexList

    # XXX: Unused
    # Returns the assigned value to the target register
    def getAssignedValueByRegister(self, method, register):
        for instruction in method:
            if "const/" in instruction and register in instruction:
                registerEnd = instruction.find(",")
                registerBegin = instruction.find(" ", 0, registerEnd) + 1
                return instruction[registerBegin:registerEnd]

        return None

    # XXX: Unused
    def hasOperationProceed(self, instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if 'Landroid/webkit/SslErrorHandler;->proceed()V' in instructions[i]:
                return True

        return False

    # XXX: Testing (called externally - 2nd)
    def doesPreferenceActivityHasValidFragmentCheck(self, activity):
        if activity.startswith("."):
            activityName = self.apk.apk.get_package() + activity
        else:
            activityName = activity

        activityName = activityName.replace(".", "/")

        # Check if activity location was previously found
        if activity in self.activityLocations:
            res = [self.activityLocations[activity]]
        else:
            grep = Grep("\.class public([a-zA-Z\s]*)L" + activity + ";", self.dir_exclusions, self.file_exclusions)
            res = grep.check_directories(self.smaliPaths)

        if not res:
            log.warning("Could not find file for activity: %s", activity)

        for file_path in res:
            self.activityLocations[activity] = file_path

            grep = Grep("\.super Landroid\/preference\/PreferenceActivity;", self.dir_exclusions, self.file_exclusions)
            if grep.check_file(file_path):
                log.warning("PreferenceActivity on: %s", file_path)
                method = self.getMethod(r"\.method protected isValidFragment\(Ljava\/lang\/String;\)Z", r"\.end method", file_path)

                log.warning("isValidFragment() method: %s", "\n".join(method))
                if method:
                    return True
                else:
                    return False

    # XXX: Testing (called externally - 1st)
    # https://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE
    # https://stackoverflow.com/questions/32440679/flag-secure-not-working-on-dialogfragment-with-style-as-dialogfragment-style-no/37491066#37491066
    def doesActivityHasFlagSecure(self, activity):
        if activity.startswith("."):
            activityName = self.apk.apk.get_package() + activity
        else:
            activityName = activity

        activityName = activityName.replace(".", "/")

        grep = Grep("\.class public([a-zA-Z\s]*)L" + activityName + ";", self.dir_exclusions, self.file_exclusions)
        res = grep.check_directories(self.smaliPaths)

        if not res:
            log.warning("Could not find file for activity: %s", activity)

        for file_path in res:
            self.activityLocations[activity] = file_path

            method = self.getMethod(r"\.method ([a-zA-Z]*) onCreate\(Landroid\/os\/Bundle;\)V", r"\.end method", file_path)
            register = self.findRegisterByAssignedValue(method, "0x2000")
            if not register:
                return False

            # invoke-virtual {p1, v0, v0}, Landroid/view/Window;->setFlags(II)V
            grep = Grep("invoke-virtual(.*)" + register + "(.*)Landroid\/view\/Window;->setFlags\(II\)V", self.dir_exclusions, self.file_exclusions)
            return grep.check_file(file_path)

    # XXX: Checked with ca.mobile.explorer
    def findDynamicRegisteredBroadcastReceivers(self):
        grep = Grep(";->registerReceiver\(Landroid\/content\/BroadcastReceiver;Landroid\/content\/IntentFilter;\)", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.dynamicRegisteredBroadcastReceiversLocations.extend(res)

    # XXX: Checked with com.android.insecurebank / ca.mobile.explorer
    def findEncryptionFunctions(self):
        grep = Grep("invoke-virtual {(.*)}, Ljavax\/crypto\/Cipher;->init\(ILjava\/security\/Key", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            if "org/bouncycastle" in location:
                continue
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Ljavax/crypto/Cipher;->init\(ILjava/security/Key")
            for index in indexList:
                registers = self.findRegistersPassedToFunction(instructions[index])
                if self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "0x1":
                    self.encryptionFunctionsLocation.append(location)
                elif self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "0x2":
                    self.decryptionFunctionsLocation.append(location)
                else:
                    self.undeterminedCryptographicFunctionsLocation.append(location)

    # XXX: Checked with ca.mobile.explorer
    def findKeystoreUsage(self):
        grep = Grep("invoke-virtual {(.*)}, Ljava\/security\/KeyStore;->getEntry\(Ljava\/lang\/String;Ljava\/security\/KeyStore\$ProtectionParameter;\)Ljava\/security\/KeyStore\$Entry", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.keystoreLocations.extend(res)

    # XXX: Checked with com.htbridge.pivaa
    def findWebViewLoadUrlUsage(self):
        grep = Grep("Landroid\/webkit\/WebView;->loadUrl\(Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.webViewLoadUrlUsageLocation.extend(res)

    # *** Improper Platform Usage ***

    # XXX: unused
    def findPathTraversalContentProvider(self):
        grep = Grep("\.super Landroid\/content\/ContentProvider;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "")
            if len(indexList) > 0:
                indexList = self.findInstructionIndex(instructions, "")

    # https://support.google.com/faqs/answer/7496913?hl=en
    # XXX: Checked with com.mwr.example.sieve
    def determineContentProviderPathTraversal(self, provider):
        provider = provider.replace("$", "\$").replace(".", "\/")
        grep = Grep("\.class .* L" + provider, self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            method = self.getMethod(r"\.method public openFile\(Landroid\/net\/Uri;Ljava\/lang\/String;\)Landroid\/os\/ParcelFileDescriptor;", r"\.end method", location)
            if not method:
                continue

            indexList = self.findInstructionIndex(method, "Ljava\/io\/File;->getCanonicalPath\(\)")
            if not indexList:
                # If file is being loaded with getCanonicalPath(), then it is probably safe
                self.vulnerableContentProvidersPathTraversalLocations.append(location)

    # XXX: Checked with com.android.insecurebank
    def determineContentProviderSQLi(self, provider):
        provider = provider.replace("$", "\$").replace(".", "\/")
        grep = Grep("\.class .* L" + provider, self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            method = self.getMethod(r"\.method public query\(Landroid\/net\/Uri;\[Ljava\/lang\/String;Ljava\/lang\/String;\[Ljava\/lang\/String;Ljava\/lang\/String;\)Landroid\/database\/Cursor;", r"\.end method", location)
            if not method:
                continue

            indexList = self.findInstructionIndex(method, "invoke-virtual(.*) {(.*)}, Landroid\/database\/sqlite\/SQLiteDatabase;->query")
            indexList.extend(self.findInstructionIndex(method, "invoke-virtual(.*) {(.*)}, Landroid\/database\/sqlite\/SQLiteQueryBuilder;->query\(Landroid/database/sqlite/SQLiteDatabase;"))

            if indexList and not self.findInstructionIndex(method, "\?"):
                self.vulnerableContentProvidersSQLiLocations.append(location)

    # XXX: Checked with sweatcoin / snapchat_9.11
    def findWeakCryptographicUsage(self):
        grep = Grep("Ljavax\/crypto\/Cipher;->getInstance\(Ljava\/lang\/String;\)Ljavax\/crypto\/Cipher;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;\)Ljavax/crypto/Cipher;")
            for index in indexList:
                register = self.findRegistersPassedToFunction(instructions[index])
                transformationValue = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[0], index)
                if transformationValue is not None:
                    if transformationValue == "\"AES\"" or "AES/ECB/" in transformationValue:
                        self.AESwithECBLocations.append(location)
                    elif "DES" in transformationValue:
                        self.DESLocations.append(location)

    # XXX: Checked with com.htbridge.pivaa
    def findPropertyEnabledWebViews(self):
        grep = Grep(";->getSettings\(\)Landroid\/webkit\/WebSettings;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)V")
            if len(indexList) > 0:
                for index in indexList:
                    register = self.findRegistersPassedToFunction(instructions[index])
                    value = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[1], index)
                    if value == "0x1":
                        self.javascriptEnabledWebviews.append(location)
            indexList = self.findInstructionIndex(instructions, "Landroid/webkit/WebSettings;->setAllowFileAccess\(Z\)V")
            if len(indexList) > 0:
                for index in indexList:
                    register = self.findRegistersPassedToFunction(instructions[index])
                    value = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[1], index)
                    if value == "0x1":
                        self.fileAccessEnabledWebviews.append(location)
            else:
                self.fileAccessEnabledWebviews.append(location)
            indexList = self.findInstructionIndex(instructions, "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs\(Z\)V")
            if len(indexList) > 0:
                for index in indexList:
                    register = self.findRegistersPassedToFunction(instructions[index])
                    value = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[1], index)
                    if value == "0x1":
                        self.universalAccessFromFileURLEnabledWebviewsLocations.append(location)

    # XXX: Checked with dvhma.featherweight
    def findWebviewJavascriptInterfaceUsage(self):
        grep = Grep(";->addJavascriptInterface\(Ljava\/lang\/Object;Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, ";->addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V")
            if len(indexList) != 0:
                for index in indexList:
                    registers = self.findRegistersPassedToFunction(instructions[index])
                self.webViewAddJavascriptInterfaceUsageLocation.append(location)

    # *** Insecure Communication Checks ***

    # Check for the implementation of custom HostnameVerifiers
    # XXX: Checked with com.htbridge.pivaa
    def checkInsecureHostnameVerifier(self):
        # .implements Ljavax/net/ssl/HostnameVerifier;
        grep = Grep("\.implements Ljavax\/net\/ssl\/HostnameVerifier;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            method = self.getMethod(r"\.method .* verify\(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;\)Z", r"\.end method", location)
            if not method:
                continue

            if self.doesMethodReturnTrue(method) is True:
                self.vulnerableHostnameVerifiers.append(location)

    # Check for the presence of the custom function that allows to bypass SSL errors in WebViews
    # XXX: Checked with dvhma.featherweight
    def checkWebviewSSLErrorBypass(self):
        grep = Grep("Landroid\/webkit\/SslErrorHandler;->proceed\(\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.vulnerableWebViewSSLErrorBypass.extend(res)

    # Check for the presence of custom TrustManagers that are vulnerable.
    # XXX: Checked with com.htbridge.pivaa
    def checkVulnerableTrustManagers(self):
        grep = Grep("\.method public checkClientTrusted\(\[Ljava\/security\/cert\/X509Certificate;Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            method = self.getMethod(r"\.method public checkClientTrusted\(", r"\.end method", location)
            if not method:
                continue

            if not self.isMethodEmpty(method):
                continue

            grep = Grep("\.method public getAcceptedIssuers\(\)\[Ljava\/security\/cert\/X509Certificate;", self.dir_exclusions, self.file_exclusions)

            if grep.check_file(location):

                method = self.getMethod(r"\.method public getAcceptedIssuers\(\)\[Ljava\/security\/cert\/X509Certificate;", r"\.end method", location)
                if not method:
                    continue
                # new-array v0, v0, [Ljava/security/cert/X509Certificate;
                if not self.doesMethodReturnNull(method, "new-array v0, v0, [Ljava/security/cert/X509Certificate;"):
                    continue

                grep = Grep("\.method public checkServerTrusted\(\[Ljava\/security\/cert\/X509Certificate;Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

                if grep.check_file(location):
                    method = self.getMethod(r"\.method public checkServerTrusted\(", r"\.end method", location)
                    if self.isMethodEmpty(method):
                        self.vulnerableTrustManagers.append(location)

    # Check for the presence of setHostnameVerifier with ALLOW_ALL_HOSTNAME_VERIFIER
    # XXX: Checked with sweatcoin
    def checkVulnerableHostnameVerifiers(self):
        grep = Grep("invoke-virtual {(.*)}, Lorg\/apache\/http\/conn\/ssl\/SSLSocketFactory;->setHostnameVerifier\(Lorg\/apache\/http\/conn\/ssl\/X509HostnameVerifier;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Lorg/apache/http/conn/ssl/SSLSocketFactory;->setHostnameVerifier")
            for index in indexList:
                registers = self.findRegistersPassedToFunction(instructions[index])
                if self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;":
                    self.vulnerableSetHostnameVerifiers.append(location)

    # Check for SocketFactory without Hostname Verify
    # https://op-co.de/blog/posts/java_sslsocket_mitm/
    def checkVulnerableSockets(self):
        grep = Grep("Ljavax\/net\/SocketFactory;->createSocket\(Ljava\/lang\/String;I\)Ljava\/net\/Socket;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Ljavax/net/ssl/HostnameVerifier;->verify\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z")
            if indexList:
                self.vulnerableSocketsLocations.append(location)

    # Check for the implementation of OKHttp Certificate Pinning
    def checkOKHttpCertificatePinning(self):
        grep = Grep("add\(Ljava\/lang\/String;\[Ljava\/lang\/String;\)Lokhttp3\/CertificatePinner\$Builder", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            # Bypass library files
            if "/okhttp" in location:
                continue

            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "certificatePinner\(Lokhttp3/CertificatePinner;\)Lokhttp3/OkHttpClient$Builder;")
            if indexList:
                self.okHttpCertificatePinningLocation.append(location)

    # Check for custom Certificate Pinning Implementation
    # XXX: Checked with com.application.zomato
    def checkCustomPinningImplementation(self):
        grep = Grep("invoke-virtual {(.*)}, Ljavax\/net\/ssl\/TrustManagerFactory;->init\(Ljava\/security\/KeyStore;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            if "/okhttp" in location or "io/fabric" in location:
                continue

            self.customCertifificatePinningLocation.append(location)

    # *** CUSTOM CHECKS ***

    def findCustomChecks(self, checks):
        for check in checks:
            self.customChecksLocations[check[0]] = []
            grep = Grep(check[1])

            res = grep.check_directories(self.smaliPaths)
            self.customChecksLocations[check[0]].extend(res)

    # *** GETTERS ***

    def get_analysis(self):
        attrs = [
            "vulnerableTrustManagers",
            "vulnerableWebViewSSLErrorBypass",
            "vulnerableHostnameVerifiers",
            "encryptionFunctionsLocation",
            "decryptionFunctionsLocation",
            "undeterminedCryptographicFunctionsLocation",
            "vulnerableSetHostnameVerifiers",
            "vulnerableSocketsLocations",
            "webViewLoadUrlUsageLocation",
            "webViewAddJavascriptInterfaceUsageLocation",
            "AESwithECBLocations",
            "DESLocations",
            "javascriptEnabledWebviews",
            "fileAccessEnabledWebviews",
            "universalAccessFromFileURLEnabledWebviewsLocations",
            "okHttpCertificatePinningLocation",
            "customCertifificatePinningLocation",
            "keystoreLocations",
            "dynamicRegisteredBroadcastReceiversLocations",
            "vulnerableContentProvidersSQLiLocations",
            "vulnerableContentProvidersPathTraversalLocations",
            "customChecksLocations"
        ]
        data = {}
        for attr in attrs:
            value = getattr(self, attr)
            value = list(map(lambda x: os.path.relpath(x, self.apk.output_path).replace("\\", "/"), value))
            data[attr] = value

        return data

    def getVulnerableTrustManagers(self):
        return self.vulnerableTrustManagers

    def getVulnerableWebViewSSLErrorBypass(self):
        return self.vulnerableWebViewSSLErrorBypass

    def getVulnerableHostnameVerifiers(self):
        return self.vulnerableHostnameVerifiers

    def getEncryptionFunctionsLocations(self):
        return self.encryptionFunctionsLocation

    def getDecryptionFunctionsLocations(self):
        return self.decryptionFunctionsLocation

    def getUndeterminedCryptographicFunctionsLocations(self):
        return self.undeterminedCryptographicFunctionsLocation

    def getVulnerableSetHostnameVerifier(self):
        return self.vulnerableSetHostnameVerifiers

    def getVulnerableSockets(self):
        return self.vulnerableSocketsLocations

    def getWebViewsLoadUrlUsageLocations(self):
        return self.webViewLoadUrlUsageLocation

    def getCustomChecksLocations(self):
        return self.customChecksLocations

    def getWebviewAddJavascriptInterfaceLocations(self):
        return self.webViewAddJavascriptInterfaceUsageLocation

    def getAESwithECBLocations(self):
        return self.AESwithECBLocations

    def getDESLocations(self):
        return self.DESLocations

    def getJavascriptEnabledWebViews(self):
        return self.javascriptEnabledWebviews

    def getFileAccessEnabledWebViews(self):
        return self.fileAccessEnabledWebviews

    def getUniversalAccessFromFileURLEnabledWebviewsLocations(self):
        return self.universalAccessFromFileURLEnabledWebviewsLocations

    def getOkHTTPCertificatePinningLocations(self):
        return self.okHttpCertificatePinningLocation

    def getCustomCertificatePinningLocations(self):
        return self.customCertifificatePinningLocation

    def getKeystoreLocations(self):
        return self.keystoreLocations

    def getDynamicRegisteredBroadcastReceiversLocations(self):
        return self.dynamicRegisteredBroadcastReceiversLocations

    def getVulnerableContentProvidersSQLiLocations(self):
        return self.vulnerableContentProvidersSQLiLocations

    def getVulnerableContentProvidersPathTraversalLocations(self):
        return self.vulnerableContentProvidersPathTraversalLocations
