# DroidSF: Android Security Framework

## Requirements
- Git
- Python 3
- Java JDK
- Android Studio + Android SDK

## Setup - Windows

### 1. Install Java Development Kit 8 - [Download](https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)

Setup environment variables:
- `JAVA_HOME`: `C:\Program Files\Java\jdk1.8.0_201`
- Add to `PATH`: `%JAVA_HOME%\bin`

### 2. Install Android Studio (includes Android SDK) - [Download](https://developer.android.com/studio/)

Setup environment variables (defaults on Windows):
- `ANDROID_SDK`: `%UserProfile%\AppData\Local\Android\Sdk`
- `ANDROID_SDK_HOME`: `%UserProfile%`

**Note**: `ANDROID_SDK` and `ANDROID_SDK_HOME` can not point to the same directory.

- Add to `$PATH`: `%ANDROID_SDK%\platform-tools`
- Add to `$PATH`: `%ANDROID_SDK%\tools` (optional)

**Note**: new AVDs will be created under: `%ANDROID_SDK_HOME%\.android\avd`


### 2. Setup Android Virtual Device (AVD) in Android Studio

Make sure you have `java` and `adb` on your global path.

Start Android Studio > Configure > AVD Manager > Create Virtual Device:
 - Nexus 5X
 - x86 images: Oreo - API level 27 - ABI x86

This setup seems to work fine with current release of Frida.

**Limitation**: Applications with native libraries only for ARM architecures (e.g. armeabi-v7a) will not work. Without getting your hopes high, check out: libhoudini.

### 2. Install Python 3 - [Download](https://www.python.org/downloads/)

### 3. Install Frida + Frida-Tools
```
py -3 -m pip install frida frida-tools
```

```
py -3 -m pip install -r requirements.txt --upgrade
```

### 4. Download frida-server for device

https://github.com/frida/frida/releases

- iOS ARM - frida-server-12.3.1-ios-arm.xz / frida-server-12.3.1-ios-arm64.xz
- Android x86 emulator - frida-server-12.3.1-android-x86.xz / -frida-server-12.3.1-android-x86_64.xz
- Android ARM device - frida-server-12.3.1-android-arm.xz / frida-server-12.3.1-android-arm64.xz

Extract frida-server binary.

### 5. Upload and start frida-server on device

```
adb root # might be required
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### 6. Start frida CLI
```
C:\Python37\Scripts\frida.exe -U frida-server
```
Test it by typing: `Java.androidVersion` - it should output the Android OS version.

## Frida script framework

### Install

```
py -3 -m pip install -r requirements.txt
```

## Build Enjarify PEX

pip3 install pex
git clone git@github.com:neskk/enjarify.git
cd enjarify

python3 -m pex -v --disable-cache . -e enjarify.main -o bin/enjarify.pex --python=python3

## Usage

```
usage: script.py [-h] [-cf CONFIG] [-v] -a APK_FILE [-d] [--force]
                 [--force-download] [--cache-path CACHE_PATH]
                 [--download-path DOWNLOAD_PATH] [--log-path LOG_PATH]
                 [--output-path OUTPUT_PATH] [--arch {arm,arm64,x86,x86_64}]
                 [--dex-converter {enjarify,dex2jar}]
                 [--java-decompiler {cfr,procyon}]
                 [--frida-version FRIDA_VERSION] [-s SCRIPT]
                 [--file-exclusions FILE_EXCLUSIONS]
                 [--directory-exclusions DIRECTORY_EXCLUSIONS]
                 [--custom-checks CUSTOM_CHECKS] [--java_home JAVA_HOME]
                 [--android_sdk ANDROID_SDK]
```
Args that start with '--' (eg. -v) can also be set in a config file (config/config.ini or specified via -cf).

Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi).
If an argument is specified in more than one place, then commandline values override config file values which override defaults.

```
arguments:
  -h, --help            show this help message and exit
  -cf CONFIG, --config CONFIG
                        Set configuration file.
  -v, --verbose         Run in the verbose mode.
  -a APK_FILE, --apk-file APK_FILE
                        Path to APK to analyse.
  -d, --decompile       Decompile APK DEX into Java source code.
  --force               Overrides previously generated files.
  --force-download      Overrides previously downloaded files.
  --cache-path CACHE_PATH
                        Directory where temporary files are saved.
  --download-path DOWNLOAD_PATH
                        Directory where downloaded files are saved.
  --log-path LOG_PATH   Directory where log files are saved.
  --output-path OUTPUT_PATH
                        Directory where generated files are saved.
  --arch {arm,arm64,x86,x86_64}
                        Android device architecture. Default: x86
  --dex-converter {enjarify,dex2jar}
                        DEX to JAR converter. Default: enjarify
  --java-decompiler {cfr,procyon}
                        JAR to Java decompiler. Default: procyon
  --frida-version FRIDA_VERSION
                        Specify which frida version to use.Note: must match
                        python package version.
  -s SCRIPT, --script SCRIPT
                        Script to execute.
  --file-exclusions FILE_EXCLUSIONS
                        Ignore these paths/files on static analysis
  --directory-exclusions DIRECTORY_EXCLUSIONS
                        Ignore these directories on static analysis.
  --custom-checks CUSTOM_CHECKS
                        Additional checks to smali code.
  --java_home JAVA_HOME
                        Directory that contains Java executables. [env var:
                        JAVA_HOME]
  --android_sdk ANDROID_SDK
                        Directory that contains Android SDK executables. [env
                        var: ANDROID_SDK]
```

## Credits

https://github.com/clviper/droidstatx

https://github.com/b-mueller/apkx

https://www.frida.re/docs/android/

https://github.com/frida/frida-python/tree/master/examples

https://github.com/11x256/frida-android-examples

http://asvid.github.io/android-frida-hacking

https://github.com/b-mueller/frida-detection-demo

- Dex2jar - https://github.com/pxb1988/dex2jar
- CFR - http://www.benf.org/other/cfr/
