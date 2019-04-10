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

    def __init__(self, args, apkName):
        self.dir_exclusions = args.directory_exclusions
        self.file_exclusions = args.file_exclusions
        self.apkPath = os.path.join(args.output_path, apkName)
        for root, dirs, files in os.walk(self.apkPath, topdown=False):
            for name in dirs:
                if "smali" in name:
                    path = os.path.join(root, name)
                    self.smaliPaths.append(path)

        if args.verbose:
            self.getMethod = droidsf.utils.timeit(self.getMethod)

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
        self.findPathTraversalContentProvider()
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

        if not res:
            log.info("getMethod( %s , %s ) empty on %s", startPattern, endPattern, filePath)
        else:
            log.debug("getMethod( %s , %s ) on %s matched %d lines. ", startPattern, endPattern, filePath, len(res))
            # if len(res) < 10:
            #     log.info("\n%s", "\n".join(res))
        return res

    # https://www.tutorialspoint.com/sed/sed_pattern_range.htm
    @droidsf.utils.timeit
    def getMethodCompleteInstructions(self, methodRegEx, filePath):
        command = ["sed", "-n", methodRegEx, filePath]
        # log.info(" ".join(command))
        sed = Popen(command, stdout=PIPE, universal_newlines=True)
        out = sed.communicate()[0]
        methodContent = out.strip().split('\n')
        methodContent = [l.strip() for l in methodContent if l.strip()]

        if not methodContent:
            log.info("sed search %s empty on %s", methodRegEx, filePath)
        else:
            log.debug("sed search %s on %s matched %d lines. ", methodRegEx, filePath, len(methodContent))

        # if len(methodContent) < 10:
        #     log.info("\n%s", "\n".join(methodContent))
        return methodContent

    def getMethodInstructions(self, methodRegEx, filePath):
        command = ["sed", "-n", methodRegEx, filePath]
        log.info(" ".join(command))
        sed = Popen(command, stdout=PIPE, universal_newlines=True)
        methodContent = sed.communicate()[0]
        try:
            match = re.search(r"\.locals \d{1,}([\S\s]*?)\.end method", methodContent)
            instructions = str(match.group(1)).strip().replace('    ', '').split('\n')
            return instructions
        except:
            return ""

    def isMethodEmpty(self, instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if instructions[i] == '.end method':
                continue
            else:
                if instructions[i] == "return-void":
                    return True
                else:
                    return False

    def hasOperationProceed(self, instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if 'Landroid/webkit/SslErrorHandler;->proceed()V' in instructions[i]:
                return True
            else:
                continue
        return False

    def doesMethodReturnNull(self, instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if instructions[i] == "return-object v0":
                if i - 1 >= 0 and instructions[i - 1] == "const/4 v0, 0x0":
                    return True
                elif i - 1 >= 0 and instructions[i - 1] == "new-array v0, v0, [Ljava/security/cert/X509Certificate;":
                    if i - 2 >= 0 and instructions[i - 2] == "const/4 v0, 0x0":
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                continue
        return False

    def doesMethodReturnTrue(self, instructions):
        maxLen = len(instructions) - 1
        for i in range(maxLen, 0, -1):
            if instructions[i] == "return v0":
                if i - 1 >= 0 and instructions[i - 1] == "const/4 v0, 0x1":
                    return True
                else:
                    return False
            else:
                continue
        return False

    # Returns the register that has the target value assigned
    def searchRegisterByAssignedValue(self, method, value):
        register = ""
        for instruction in method:
            if "const/" in instruction and value in instruction:
                registerEnd = instruction.find(",")
                registerBegin = instruction.find(" ", 0, registerEnd) + 1
                register = instruction[registerBegin:registerEnd]
                break
        return register

    # Returns the assigned value to the targer register.
    def getAssignedValueByRegister(self, instructions, register):
        register = ""
        for instruction in instructions:
            if "const/" in instruction and register in instruction:
                registerEnd = instruction.find(",")
                registerBegin = instruction.find(" ", 0, registerEnd) + 1
                register = instruction[registerBegin:registerEnd]
                break
        return register

    def doesActivityExtendsPreferenceActivity(self, activity):
        activity = activity.replace(".", "/")
        grep = Grep("\.class public([a-zA-Z\s]*)L" + activity + ";", self.dir_exclusions, self.file_exclusions)
        res = grep.check_directories(self.smaliPaths)

        for file_path in res:
            grep = Grep("\.super Landroid\/preference\/PreferenceActivity;", self.dir_exclusions, self.file_exclusions)
            return grep.check_file(file_path)

    def doesPreferenceActivityHasValidFragmentCheck(self, activity):
        activity = activity.replace(".", "/")
        grep = Grep("\.class public([a-zA-Z\s]*)L" + activity + ";", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for file_path in res:
            grep = Grep("\.super Landroid\/preference\/PreferenceActivity;", self.dir_exclusions, self.file_exclusions)
            if grep.check_file(file_path):
                isValidFragmentFunction = self.getMethodCompleteInstructions('/.method protected isValidFragment(Ljava\/lang\/String;)Z/,/^.end method/p', file_path)
                isValidFragmentFunction = self.getMethod(r"\.method protected isValidFragment\(Ljava\/lang\/String;\)Z", r"\.end method", file_path)
                if isValidFragmentFunction:
                    return True
                else:
                    return False

    # Checked
    def doesActivityHasFlagSecure(self, activity):
        activity = activity.replace(".", "/")
        end = activity.rfind('/') + 1

        for smaliPath in self.smaliPaths:
            activityPath = os.path.join(smaliPath, activity[:end])

            grep = Grep("\.class public([a-zA-Z\s]*)L" + activity + ";", self.dir_exclusions, self.file_exclusions)
            res = grep.check_directory(activityPath)

            for file_path in res:
                methodInstructions = self.getMethodCompleteInstructions('/.method \([a-zA-Z]* \)onCreate(Landroid\/os\/Bundle;)V/,/^.end method/p', file_path)
                method = self.getMethod(r"\.method [a-zA-Z]* onCreate\(Landroid\/os\/Bundle;\)V", r"\.end method", file_path)
                register = self.searchRegisterByAssignedValue(method, "0x2000")
                if register.strip() == "":
                    return False
                else:
                    grep = Grep("invoke-virtual.*" + register + ".*Landroid\/view\/Window;->setFlags\(II\)V", self.dir_exclusions, self.file_exclusions)
                    return grep.check_file(file_path)

    def findRegisterAssignedValueFromIndexBackwards(self, instructionsList, register, index):
        for pointer in range(index, 0, -1):
            if register in instructionsList[pointer] and ("const" in instructionsList[pointer] or "sget-object" in instructionsList[pointer]):
                valueBegin = instructionsList[pointer].find(",")
                value = instructionsList[pointer][valueBegin + 2:]
                return value

    def findRegistersPassedToFunction(self, functionInstruction):
        match = re.search(r"{(.*)}", functionInstruction)
        try:
            if "range" in functionInstruction:
                registers = str(match.group(1)).strip().replace(' ', '').split("..")
            else:
                registers = str(match.group(1)).strip().replace(' ', '').split(",")
        except:
            match = re.search(r"\D\d", functionInstruction)
            try:
                registers = str(match.group(0))
            except:
                return ""
        return registers

    def findInstructionIndex(self, instructionsList, instructionToSearch):
        indexList = []
        regex = re.compile(instructionToSearch)
        for index, instruction in enumerate(instructionsList):
            m = re.search(regex, instruction)
            try:
                output = m.group(0)
                indexList.append(index)
            except:
                continue
        return indexList

    def findDynamicRegisteredBroadcastReceivers(self):
        grep = Grep(";->registerReceiver\(Landroid\/content\/BroadcastReceiver;Landroid\/content\/IntentFilter;\)", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.dynamicRegisteredBroadcastReceiversLocations.extend(res)

    def findEncryptionFunctions(self):
        grep = Grep("invoke-virtual {(.*)}, Ljavax\/crypto\/Cipher;->init\(ILjava\/security\/Key", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            if "org/bouncycastle" in location:
                continue
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Ljavax/crypto/Cipher;->init\(ILjava/security/Key")
            if len(indexList) != 0:
                for index in indexList:
                    registers = self.findRegistersPassedToFunction(instructions[index])
                    if self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "0x1":
                        self.encryptionFunctionsLocation.append(location)
                    elif self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "0x2":
                        self.decryptionFunctionsLocation.append(location)
                    else:
                        if location not in self.undeterminedCryptographicFunctionsLocation:
                            self.undeterminedCryptographicFunctionsLocation.append(location)

    def findKeystoreUsage(self):
        grep = Grep("invoke-virtual {(.*)}, Ljava\/security\/KeyStore;->getEntry\(Ljava\/lang\/String;Ljava\/security\/KeyStore\$ProtectionParameter;\)Ljava\/security\/KeyStore\$Entry", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.keystoreLocations.extend(res)

    def findWebViewLoadUrlUsage(self):
        grep = Grep("Landroid\/webkit\/WebView;->loadUrl\(Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.webViewLoadUrlUsageLocation.extend(res)

    # *** Improper Platform Usage ***

    def findPathTraversalContentProvider(self):
        grep = Grep("\.super Landroid\/content\/ContentProvider;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "")
            if len(indexList) > 0:
                indexList = self.findInstructionIndex(instructions, "")

    def determineContentProviderPathTraversal(self, provider):
        provider = provider.replace("$", "\$").replace(".", "/")
        grep = Grep("\.class .* L" + provider, self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getMethodCompleteInstructions('/.method public openFile(Landroid\/net\/Uri;Ljava\/lang\/String;)Landroid\/os\/ParcelFileDescriptor;/,/^.end method/p', location)
            method = self.getMethod(r"\.method public openFile\(Landroid\/net\/Uri;Ljava\/lang\/String;\)Landroid\/os\/ParcelFileDescriptor;", r"\.end method", location)
            indexList = self.findInstructionIndex(instructions, "Ljava\/io\/File;->getCanonicalPath\(\)")
            if len(indexList) > 0:
                self.vulnerableContentProvidersPathTraversalLocations.append(location)

    def determineContentProviderSQLi(self, provider):
        provider = provider.replace("$", "\$").replace(".", "/")
        grep = Grep("\.class .* L" + provider, self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getMethodCompleteInstructions('/.method public query(Landroid\/net\/Uri;\[Ljava\/lang\/String;Ljava\/lang\/String;\[Ljava\/lang\/String;Ljava\/lang\/String;)Landroid\/database\/Cursor;/,/^.end method/p', location)
            method = self.getMethod(r"\.method public query\(Landroid\/net\/Uri;\[Ljava\/lang\/String;Ljava\/lang\/String;\[Ljava\/lang\/String;Ljava\/lang\/String;\)Landroid\/database\/Cursor;", r"\.end method", location)

            indexList = self.findInstructionIndex(instructions, "invoke-virtual(.*) {(.*)}, Landroid\/database\/sqlite\/SQLiteDatabase;->query")
            if len(indexList) > 0:
                indexList = self.findInstructionIndex(instructions, "\?")
                if len(indexList) == 0:
                    self.vulnerableContentProvidersSQLiLocations.append(location)

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
    # XXX: Checked
    def checkInsecureHostnameVerifier(self):
        # .implements Ljavax/net/ssl/HostnameVerifier;
        grep = Grep("\.implements Ljavax\/net\/ssl\/HostnameVerifier;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            methodInstructions = self.getMethodCompleteInstructions('/.method .* verify(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;)Z/,/^.end method/p', location)
            method = self.getMethod(r"\.method .* verify\(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;\)Z", r"\.end method", location)
            if not method:
                continue

            if self.doesMethodReturnTrue(method) is True:
                self.vulnerableHostnameVerifiers.append(location)

    # Check for the presence of the custom function that allows to bypass SSL errors in WebViews
    def checkWebviewSSLErrorBypass(self):
        grep = Grep("Landroid\/webkit\/SslErrorHandler;->proceed\(\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        self.vulnerableWebViewSSLErrorBypass.extend(res)

    # Check for the presence of custom TrustManagers that are vulnerable.
    def checkVulnerableTrustManagers(self):
        grep = Grep("\.method public checkClientTrusted\(\[Ljava\/security\/cert\/X509Certificate;Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            methodInstructions = self.getMethodCompleteInstructions('/.method public checkClientTrusted\(\)/,/^.end method/p', location)
            method = self.getMethod(r"\.method public checkClientTrusted\(", r"\.end method", location)
            if methodInstructions == "":
                continue

            if not self.isMethodEmpty(methodInstructions):
                continue

            grep = Grep("\.method public getAcceptedIssuers\(\)\[Ljava\/security\/cert\/X509Certificate;", self.dir_exclusions, self.file_exclusions)

            if grep.check_file(location):

                methodInstructions = self.getMethodCompleteInstructions('/.method public getAcceptedIssuers()\[Ljava\/security\/cert\/X509Certificate;/,/^.end method/p', location)
                method = self.getMethod(r"\.method public getAcceptedIssuers\(\)\[Ljava\/security\/cert\/X509Certificate;", r"\.end method", location)
                if methodInstructions == "":
                    continue

                if not self.doesMethodReturnNull(methodInstructions):
                    continue

                grep = Grep("\.method public checkServerTrusted\(\[Ljava\/security\/cert\/X509Certificate;Ljava\/lang\/String;\)V", self.dir_exclusions, self.file_exclusions)

                if grep.check_file(location):
                    methodInstructions = self.getMethodCompleteInstructions('/method public checkServerTrusted\(\)/,/^.end method/p', location)
                    method = self.getMethod(r"\.method public checkServerTrusted\(", r"\.end method", location)
                    if self.isMethodEmpty(methodInstructions):
                        self.vulnerableTrustManagers.append(location)

    # Check for the presence of setHostnameVerifier with ALLOW_ALL_HOSTNAME_VERIFIER
    def checkVulnerableHostnameVerifiers(self):
        grep = Grep("invoke-virtual {(.*)}, Lorg\/apache\/http\/conn\/ssl\/SSLSocketFactory;->setHostnameVerifier\(Lorg\/apache\/http\/conn\/ssl\/X509HostnameVerifier;\)V", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Lorg/apache/http/conn/ssl/SSLSocketFactory;->setHostnameVerifier")
            if len(indexList) != 0:
                for index in indexList:
                    registers = self.findRegistersPassedToFunction(instructions[index])
                    if self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;":
                        self.vulnerableSetHostnameVerifiers.append(location)

    # Check for SocketFactory without Hostname Verify
    def checkVulnerableSockets(self):
        grep = Grep("Ljavax\/net\/SocketFactory;->createSocket\(Ljava\/lang\/String;I\)Ljava\/net\/Socket;", self.dir_exclusions, self.file_exclusions)

        res = grep.check_directories(self.smaliPaths)

        for location in res:
            instructions = self.getFileContent(location)
            indexList = self.findInstructionIndex(instructions, "Ljavax/net/ssl/HostnameVerifier;->verify\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z")
            if len(indexList) == 0:
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
            if len(indexList) == 0:
                self.okHttpCertificatePinningLocation.append(location)

    # Check for custom Certificate Pinning Implementation
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
            value = list(map(lambda x: os.path.relpath(x, self.apkPath), value))
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
