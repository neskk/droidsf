# DroidSF: Android Security Framework

## Credits

https://github.com/clviper/droidstatx

https://github.com/b-mueller/apkx

https://www.frida.re/docs/android/

https://github.com/11x256/frida-android-examples

http://asvid.github.io/android-frida-hacking

https://github.com/b-mueller/frida-detection-demo


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

### Usage

```
usage: script.py [-h] [-cf CONFIG] [-v] [--log-path LOG_PATH] [-s SCRIPT]
                 [-a APP]
```
Args that start with '--' (eg. -v) can also be set in a config file (config/config.ini or specified via -cf).

Config file syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at https://goo.gl/R74nmi).
If an argument is specified in more than one place, then commandline values override config file values which override defaults.

```
optional arguments:
  -h, --help            show this help message and exit
  -cf CONFIG, --config CONFIG
                        Set configuration file.
  -v, --verbose         Run in the verbose mode.
  --log-path LOG_PATH   Directory where log files are saved.
  -s SCRIPT, --script SCRIPT
                        Script to execute.
  -a APP, --app APP     App name to instrument.
