% Android Reverse Engineering for the Brave
% Axelle Apvrille
% October 2018

# Setup

You need:

- a 64-bit laptop
- [Docker](https://www.docker.com/)
- the Android samples for the lab: those will be provided on a **USB key** during the lab.
- Have at least **6GB** of free disk space

## Contents of the USB key

The USB key contains:

- **Instructions**: such as *this guide* for the lab, and also a [cheat sheet](./cheatsheet.html) of various commands.
- **Tools**: JEB Demo 3.0, and Jython (needed for JEB scripts)
- **Samples**: malicious samples to inspect during the lab. I'll explain which one to use for each lab.
- **[Solutions](./soluce.html)**: if you are stuck...

**Copy USB key's content to a given directory on your laptop**.

**If you didn't get any USB key**, you can get most stuff from [my owndrive share](https://my.owndrive.com/index.php/s/knozCAAZlXyPrCb).

> **Disclaimer**: most Android samples for this training are **malicious**.
Do **not** install them on your Android smartphones, tablets, TVs etc.
**Do not share, do not propagate, act responsibly thanks!**

| Filename | SHA256 | Comments |
| -------- | ------ | -------- |
| clipper.apk | ec14c8cac492c6170d57e0064a5c6ca31da3011a9d1512675c266cc6cc46ec8d | Android/Clipper.A!tr (August 2018) |
| kevdroid.apk | b318ec859422cbb46322b036d5e276cf7a6afc459622e845461e40a328ca263e  | Android/KevDroid.A!tr (April 2018) |
| mysterybot.apk | 62a09c4994f11ffd61b7be99dd0ff1c64097c4ca5806c5eca73c57cb3a1bc36a | Android/Locker.KV!tr (June 2018) aka MysteryBot, Marcher |
| lokibot.apk | bae9151dea172acceb9dfc27298eec77dc3084d510b09f5cda3370422d02e851 | Android/Locker.KV!tr (October 2017) |

Table: Malicious Samples to study during the workshop


## Docker 

### Installation

- Install [Docker](https://docs.docker.com/install/) on your host, make sure it works. The *free Community Edition* is fine for this workshop.
- Pull the image:
```bash
$ docker pull cryptax/android-re:latest
```
- **Run** the container:
```bash
$ docker run -d --name workshop-android -p 5022:22 -p 5900:5900 -v /DIR:/data cryptax/android-re
```

Explanations:

- **5022** is the **port to access the container's SSH server**. You can customize that if you wish.
- **5900** is the port to access the container's **VNC server**. Same you can change it too. You don't need this if you do not intend to connect via VNC.
- **`DIR`**: this is to share the directory where you copied the contents of the USB key. Replace `DIR` with an **absolute path**.
- **`workshop-android`** is a *name* for the container. Pick up whatever you wish, it is just a label.

### Log in to the container

Then, you need to connect to the container. There are two options:

- **SSH**. Use **option -X** to forward X Window and **-p** to specify the port number. This is the simplest because you don't have to install anything else, but there are some **known issues on some hosts, on Mac** for instance.
```bash
$ ssh -X -p 5022 root@127.0.0.1
```

- **VNC**. Install a vnc viewer on your host (`sudo apt-get install vncviewer`) and get access to the container. **On Mac, there seems to be an issue with the default vnc viewer, please install `vncviewer`.**

```bash
vncviewer 127.0.0.1::5900
```

### Credentials for Docker container

- Account is `root`.
- Password is **rootpass**.

### I don't want to use Docker!

#### Alternative 1: install all tools yourself

You're on your own here, but it's not that difficult, because you can basically follow the commands that Dockerfile issues (to automatically build the image) and run them manually.

The Dockerfile can be downloaded from [GitHub](https://github.com/cryptax/androidre).

#### Alternative 2: [VirtualBox](https://www.virtualbox.org/wiki/Downloads) 

This [old VirtualBox image may help you out](https://mega.nz/#!uRoBXLQA!oukLE-JfJVp1qSLcS4bZrW03QnrxS1GNlKY-3cL1ltc) (5 GB). **I don't recommend it though, because this image is no longer up to date for this workshop**.

sha256: 
```
c8b14cdb10a0fd7583ea9f1a5be6c2facfaa8684b782c9fb21918f8e2ba64d5f  android-re.ova
```

Import the image of the VM (provided on the USB disk). For your information it is based on a *Xubuntu 16.04 64 bit*.

Then start the image and login on account `osboxes`. The password is **rootpass**.

**Note: the VM uses a keyboard layout en_US**
If that does not suit your own keyboard, it can be changed once you login in Main Menu > Keyboard > Layout: unclick "use system defaults", add your own keyboard and select it.

To share a folder with all the samples for the lab:

- Mount the contents of the USB disk to a directory named `/data`. 
- Open the VM Settings and go to Shared Folders. Click on the Add button and browse for the folder where the contents of the USB disk is on your host. Name that share `data`.

In the VM, type:

```bash
$ mkdir /data
$ sudo mount -t vboxsf data /data
```

####  VMWare

I haven't tested the workshop on VMWare, but have been told that the following solutions work:

a) [Import the VirtualBox .ova file in VMWare](https://blogs.vmware.com/kb/2015/04/import-oracle-virtualbox-virtual-machine-vmware-fusion-workstation-player.html). The import will take some time.
b) In a Linux-based VM in VMWare, install docker and then import my docker container `docker pull cryptax/android-re`


## Checking your lab environment


- Check your docker container is up and running (`docker ps`)
- Check you are able to log into the container (see "Log in to the container" section above)
- Check `/opt` has several pre-installed Android RE tools
- Check you have access to the contents of the USB key in `/data` directory
- Launch an Android emulator: `./emulator7 &`. This is a Bash alias (see `~/.bashrc`). Check there are no startup *errors*, then wait for the emulator to boot (very long...)

When all of this works, **you are all set up for the labs!**


# Lab 0: Reverse engineering of Android/Clipper

![](../images/clipper-icon.png)

In this lab, we'll reverse together a very recent malware named [Android/Clipper.A!tr](https://news.drweb.com/show/?i=12739&lng=en). This sample was discovered in **August 2018**.
Please retrieve sample named `clipper.apk` from the USB key and make it available to your docker container.

sha256: `ec14c8cac492c6170d57e0064a5c6ca31da3011a9d1512675c266cc6cc46ec8d`.

Then, log in the container. **From now on, the rest of the labs assume you are inside the lab's docker container.**

[You can find the solutions to this lab here](./soluce.html)

Goal:

- Learn what an APK contains
- Know how to convert a binary XML to a text XML
- Understand an Android Manifest
- Identify the main activity of an application
- Identify receiver and service classes
- Use apktool
- Understand smali files
- Convert a DEX to a JAR
- Use Androguard


# Lab 1: Reverse engineering of Android/KevDroid

![](../images/kevdroid-icon.png)

**Android/KevDroid** is a **spyware** for Android smartphones. Some instances of the malware were found in phishing emails linked to the Reaper group (aka APT37, Scarcruft, Group123, Red Eyes) [1].

[1] R. Nigam , [Reaper Group's Updated Mobile Arsenal](https://researchcenter.paloaltonetworks.com/2018/04/unit42-reaper-groups-updated-mobile-arsenal/), April 2018

In this lab, you will reverse engineer a sample of Android/KevDroid. Basically, the steps are the same as in lab 0, but this time, you are on your own. The goal of this lab is to experience tools yourself and be sure you are able to reproduce what I explained during lab 0.

Please get sample `kevdroid.apk`.
sha256: `b318ec859422cbb46322b036d5e276cf7a6afc459622e845461e40a328ca263e

*If you are already at ease with Android reverse engineering, you can skip this lab.*

## Manifest

- Q1. Convert the Android Manifest to a readable format
- Q2. What is the name of the main activity?
- Q3. List services and receivers

## Overview

- Launch `/opt/extract.sh kevdroid.apk &`.
- Navigate to the main activity (see step 1). The main activity calls a method named `startTimer()` which sets a repeating alarm every 5 minutes (600 seconds). Every 5 minutes, an intent `AlarmManager` will be sent. The AndroidManifest tells us this action is handled by a class named `AlarmReceiver`:

```xml
<receiver android:name="cake.com.update.receivers.AlarmReceiver">
   <intent-filter>
      <action android:name="cake.com.update.action.AlarmManager"/>
   </intent-filter>
</receiver>
```

- Find the `AlarmReceiver` class and locate the `onReceive()` method in that class.

**Q4**. Use androguard to decompile correctly onReceive() of AlarmReceiver. If necessary, use the [cheat sheet](./cheatsheet.html) to remember the commands androguard uses.

## Reverse the algorithm

**Q5**. In `onReceive()` what do those line roughly do? *I am not asking for a detailed analysis but an overall description of what the malware does.*


```java
try {
  cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Account.txt").toString(), this.getAllAccounts().toString());
  cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Sms.txt").toString(), this.getAllSMSJSON().toString());
  cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Contact.txt").toString(), this.getAllContactsJSON().toString());
  cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Calllog.txt").toString(), this.getCallLogJSON().toString());
```

**Q6**. What do the following lines in `onReceive()` do? What is the algorithm? What is the key?


```
 cake.com.update.libraries.ZipHelper.zipFolder(v1_1.getAbsolutePath(), v2_1.getAbsolutePath());
 cake.com.update.libraries.CryptHelper.encryptFile(v2_1.getAbsolutePath(), new StringBuilder().append(v2_1.getAbsolutePath()).append("-enc").toString(), "08D03B0B6BE7FBCD");
```

## CallReceiver

A `CallReceiver` is located in cake.com.update.receivers.

**Q7**. When is the CallReceiver called? What does it do?

# Lab 2. De-obfuscating Android/MysteryBot

**Android/MysteryBot** is an Android trojan banker discovered around June 2018 [2].
It can be seen as a new emanation of the LokiBot family - which we will also investigate in another lab.

Basically, it detects numerous genuine banking apps and adds malicious overlays. It also implements
typical spyware functionalities (get contacts, SMS, key logger etc) and ransomware (it encrypts all files on the external SD card).

- [2] MysteryBot a new [Android banking Trojan ready for Android 7 and 8](https://www.threatfabric.com/blogs/mysterybot__a_new_android_banking_trojan_ready_for_android_7_and_8.html) -  June 2018

Please get sample `mysterybot.apk`
sha256: `62a09c4994f11ffd61b7be99dd0ff1c64097c4ca5806c5eca73c57cb3a1bc36a`

## Question 1

The malware poses as as **Adobe Flash Player**. Its main activity is `install.apps.MainActivity`. In this activity, you will see several strings are obfuscated.

```java
 public void A() {
        Intent v0 = new Intent(P.ALLATORIxDEMO("T,Q0Z+QlT2ElT!A+Z,\u001B\u0003q\u0006j\u0006p\u0014|\u0001p\u001Dt\u0006x\u000B{"));
        v0.putExtra(H.ALLATORIxDEMO("*~/b$y/>*`;>.h?b*>\u000FU\u001DY\bU\u0014Q\u000F]\u0002^"), MainActivity.ALLATORIxDEMO);  
        v0.putExtra(P.ALLATORIxDEMO("T,Q0Z+QlT2ElP:A0Tlt\u0006q\u001Dp\u001Ae\u000Et\ft\u0016|\r{"), H.ALLATORIxDEMO("D$0>`/q?ukd#ukf.b8y$~"));
        v0.putExtra(P.ALLATORIxDEMO("$Z0V\'\u0018.Z!^\'Q"), 3); 
        try {
            this.startActivityForResult(v0, 1);
            return;
        }
        catch(Throwable v0_1) {
            v0_1.printStackTrace();
            return;
        }
    }
```    

**Q1**. Write a standalone Java program (or any other language of your choice) to de-obfuscate those strings

## JEB on MysteryBot


[JEB](https://www.pnfsoftware.com/) provides a nice **Android decompiler** used by many malware analysts.

> *Sidenote: I am not affiliated to PNF Software, just a user.*

Like *IDA Pro*, you can write scripts to modify decompiled code and make it more readable.

We are going to **write a JEB script that automatically de-obfuscates the obfuscated string you point**.

### Installing JEB

- Get a free JEB Trial demo from the USB key (`./tools`) (or [online](http://www.pnfsoftware.com/dl?jebandroid))
- Unzip it
- Run the script for your platform, for example `./jeb_linux.sh`
- Generate the license

In addition, to support JEB scripts, follow instructions in `JEBINSTALLDIR/scripts/SCRIPTS.TXT`.
You will need a stand-alone **Jython** package: you can get it on the USB key in `./tools`.

### Writing a JEB script

- Open  `mysterybot.apk` with JEB.
- Double-click on `classes.dex`
- Browse to `install.apps.MainActivity`.
- **Decompile** the MainActivity (Tab or Q should work)

To run a script, go into menu **File >  Scripts > Run Script** and select your script. See [Developer Portal](https://www.pnfsoftware.com/jeb/manual/dev/introducing-jeb-extensions/#executing-scripts).

But first, we need to write the script.



JEB scripts are written in **Python**. They inherit from `IScript` class.

```python
class Allatori(IScript):
```

We need to do some initialization and ensure a *project* (i.e analysis of a sample) is opened.

```python
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit, IXmlUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil

class JEBAllatori(IScript):

    def run(self, ctx):
        engctx = ctx.getEnginesContext()
        if not engctx:
            print('Back-end engines not initialized')
            return

        projects = engctx.getProjects()
        if not projects:
            print('There is no opened project')
            return

        if not isinstance(ctx, IGraphicalClientContext):
            print('This script must be run within a graphical client')
            return

        prj = projects[0]
```

> [JEB API documentation](https://www.pnfsoftware.com/jeb/apidoc/reference/packages.html) or in the JEB package in `./doc/apidoc.zip`

### Get the selected string

**Q2** . Write code to get the string the end-user has just selected.

To help you out:

- In our case, `ctx` is an instance of `IGraphicalClientContext`
- You must first retrieve an *active fragment* then the *active item*
- [API for IGraphicalClientContext](https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/client/api/IGraphicalClientContext.html)
- [API for IUnitView](https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/client/api/IUnitView.html)
- [API for IUnitFragment](https://www.pnfsoftware.com/jeb/apidoc/reference/com/pnfsoftware/jeb/client/api/IUnitFragment.html)

### Ask end-user

The de-obfuscation constants are not always the same. We are going to ask the end-user to input the ones to use.

To question the end-user, use `ctx.displayQuestionBox(caption, message, defaultvalue)`. displayQuestionBox returns a **string**, convert it to an integer with `int(...)`.

**Q3**. Write code to ask for the 2 constants of the *"Allatori"* algorithm

### Glue everything in

**Q4**. Put everything together to de-obfuscate a string and run your script an obfuscated string.

To help you out:

- *If you used Python* to implement the de-obfuscation in the first part, you can re-use your code for your script. *If not*, use the implementation provided in `./solutions/Allatori.py`
- The string you retrieved from the active fragment might not be exactly the right format. This is a piece of code to help you adapt it:

```python
 def prepare_string(self, thestring):
        # Typically, you'll get this as input: '"T,Q0Z+QlT2ElT!A+Z,\u001B"'
        # This is what this function outputs: u'T,Q0Z+QlT2ElT!A+Z,\x1b'
        
        # remove first and last quote
        l = len(thestring)
        s = thestring
        if thestring[0] == '"' and thestring[l-1] == '"':
            s = thestring[1:l-1]

        # handle unicode escaping
        return s.decode('unicode-escape')
```

# Lab 3. Android/LokiBot

![](../images/lokibot-icon.png)

**Android/LokiBot** aka **Locker** is another Android banking trojan [3].
Actually, it's the *father* of MysteryBot.
The LokiBot family was first discovered in 2016. Like MysteryBot, it adds phishing overlays to numerous banking applications and has
a ransomware stage. The malware is sold underground as a kit, for approximately 2000 USD in bitcoins.

The sample we study in this lab was found in October 2017.
Please get `lokibot.apk`, sha256: `bae9151dea172acceb9dfc27298eec77dc3084d510b09f5cda3370422d02e851`

[3] W. Gahr, P. Duy Phuc, N. Croese, [LokiBot - the first hybrid Android malware](https://www.threatfabric.com/blogs/lokibot_the_first_hybrid_android_malware.html), October 2017

## Radare2

[Radare2](https://github.com/radare/radare2) is a Unix-friendly reverse engineering framework. For Android, it supports the disassembly of DEX files.
It is pre-installed in your Docker containers.

### Using radare2

- Unzip the APK
- Convert the manifest to an XML format
- Locate the main activity

Then launch radare2 on the `classes.dex`:

- `r2 classes.dex`
- Analyze all: `aa` (this may take a little time)

To list functions, use command `afl`. As there are numerous, we are going to **grep and search only for MainActivity**. To do this, use `~pattern-to-grep`.

- `afl~MainActivity`

**Q1**. What methods does MainActivity have? Can you provide their prototype signature?

To disassemble a given function, use `pdf @ function-address`. If you don't want to copy/paste the address itself, `sym.function-name` will point to its address.

**Q2**. Disassemble the constructor. What does it do?

### CommandService

If we disassemble `onCreate()` of the Main Activity, we see it starts two services:

- CommandService
- and InjectService


For example, that's the portion of code that starts the `CommandService` service.
```
|           0x0002876e      22011600       new-instance v1, Landroid/content/Intent; ; 0x1b3c
|           0x00028772      1c02ee00       const-class v2, Lfsdfsdf/gsdsfsf/gjhghjg/lbljhkjblkjblkjblkj/CommandService;
|           0x00028776      703027005102   invoke-direct {v1, v5, v2}, Landroid/content/Intent.<init>(Landroid/content/Context;Ljava/lang/Class;)V ; 0x27
|           0x0002877c      6e2039051500   invoke-virtual {v5, v1}, Lfsdfsdf/gsdsfsf/gjhghjg/lbljhkjblkjblkjblkj/MainActivity.startService(Landroid/content/Intent;)Landroid/content/ComponentName; ; 0x539
```

Let's investigate `CommandService`. It is an [**IntentService**](https://developer.android.com/reference/android/app/IntentService). Intent services basically are services meant to handle intents :)

The class has a **constructor and 4 methods**:

- **constructor**: this is called when an object is instantiated
- **onCreate()**: this gets called by the system when the service is first created
- **onStartCommand()**. The [documentation](https://developer.android.com/reference/android/app/IntentService) explains this method should not be overriden for intent services. As a matter of fact, if you check its disassembly (`pdf @ ...`), you'll see it merely calls `onStartCommand()` of its parent.
- **onHandleIntent()**. This is where the payload of an intent service is. This method gets call whenever an intent is sent to the service. For example, this happens when `startService()` for CommandService is called in the main activity.
- **abideasfasfasfasfafa()**. Actually, `onHandleIntent()` doesn't do much apart calling this method `abideasfasfasfasfafa()`. That's where the interesting code lies.


- **Q3**. Get the address of  CommandService's `abideasfasfasfasfafa()`. 
- **Q4**. List all string references used in `abideasfasfasfasfafa()`.

To help you out:

- A string reference starts with `str.`. For example, `str.f.j_f_s7o1`.
- To disassemble a function, use `pdf`.
- To move to a given address use `s ADDR`. To grep, use `~`.

Let's focus on `str.f.j_f_s7o1`. This is the name of the string within Radare 2. To view the content of the string, do `Cs. @ ADDR` (or `Cs.. @ ADDR` for more details). NB. Don't forget the **dot** : Cs **dot**.
Note that the first byte contains the **length of the string**.


**Q5**. What is the exact content of `str.f.j_f_s7o1`?


### De-obfuscating strings with a Radare2 script

The strings of `abideasfasfasfasfafa()` are de-obfuscated by method `abideasfasfasfasfafa()` in class `fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.absurdityasfasfasfasfafa`.
If we disassemble this routine, we'll find that it is extremely similar to MysteryBot's de-obfuscation.

This is its reverse implementation in Python:

```python
def deobfuscate(s, key1=88, key2=3):
    result = list(s)
    # s is an obfuscated string
    i = len(s) -1
    while i >= 0:
        result[i] = chr(ord(result[i]) ^ key1)
        i = i -1
        if i >= 0:
            result[i] = chr(ord(result[i]) ^ key2)
        i = i -1
    return ''.join(result)
```

Radare2 supports Python scripts. We are going to implement a script to de-obfuscate strings from within Radare 2.
To invoke this script in Radare 2, do: `#!pipe python yourscript.py args`

**Anatomy of a Radare2 script**:

```python
import r2pipe

# open communication
r2p = r2pipe.open()

# example issuing 2 commands: seek at address 0x00025900
# followed by function disassembly at that address
r2p.cmd("s 0x00025900 ; pdf")
```

**Q6** Write the script to de-obfuscate `str.f.j_f_s7o1`

To help you out:

- The de-obfuscation routine uses constants 88 and 3
- In Radare2, to print the value at a given address, I recommend you try `p?` and choose the output format you need, like `p8` ;)
- In Python, to read arguments, you can use the sys package: `import sys` and then `sys.argv[1]` etc.
- In Python, the method `str.decode('hex')` might be helpful for some conversions


## Frida

[Frida](https://www.frida.re/) is a dynamic intrumentation toolkit. It works over several platforms, including Android.

It helps you **hook** functions. In this lab, we are going to hook the de-obfuscation method to automatically print
the de-obfuscated result to our eyes. The advantage is that we no longer need to understand how obfuscation works.
The disadvantage is that we only see deobfuscated results for strings that actually get called because this is *dynamic*.

Frida is already installed in your docker container. 
If you need to install it by yourself, it's quite easy, please [refer to the doc](https://www.frida.re/docs/installation/).

### Launch an Android emulator

First of all, launch an Android 7.1.1 emulator. In your docker container, there is an alias for that, so just run : `emulator7 &`

I do not recommend using an older emulator (encountered issues), and for this lab, please do **not** use an x86 emulator so we all have the same :)

The emulator will take a *long time* to launch. Be patient!

Meanwhile, read the next steps.

### Hooking with Frida

We want to hook `abideasfasfasfasfafa()` in class `fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.absurdityasfasfasfasfafa`.
Frida hooks are implemented in Javascript.
The anatomy of a hook is the following:

```javascript
console.log("[*] Loading Frida script for Android/LokiBot");
if (Java.available) {
    console.log("[*] Java is available");

    Java.perform(function() {
    	aclass = Java.use("a.b.c.d");
	aclass.method.implementation = function(args ...) {
	   // code for the hook
	}
    });
}
```

 - I recommend adding messages around to see what's happening: `console.log("...");`.
- To actually call the real `abideasfasfasfasfafa()` within the hook: `this.abideasfasfasfasfafa(string);` works :)

**Q7.** Write your Frida hook to display the obfuscated string and the de-obfuscated string.

### Run Frida Server

Check your emulator is operational:

```bash
# adb devices
List of devices attached
emulator-5554	device
```

Frida uses a client that runs your hook on one side, and a server, which runs on the emulator.
Let's install the server.

The correct Frida server is located in your Docker container at `/opt/frida-server`. We will push it to the emulator in a place where we can run it:

```bash
adb push /opt/frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
```

Then, connect to the emulator: `adb shell`. Inside the emulator shell, do:

```bash
generic:/ $ su
generic:/ # cd /data/local/tmp
generic:/data/local/tmp # ./frida-server

```

### Run Frida

Open another terminal on your Docker container.
Check Frida sees your emulator:

```
root@90b58e6bc8f4:/opt# frida-ls-devices
Id             Type    Name                 
-------------  ------  ---------------------
local          local   Local System         
emulator-5554  usb     Android Emulator 5554
tcp            remote  Local TCP
```

**If you don't have frida-ls-devices**: install **frida-tools**: `pip install frida-tools`.

Check Frida client is able to communicate with the server by listing process on the emulator:

```
root@90b58e6bc8f4:/opt# frida-ps -D emulator-5554
  PID  Name
-----  --------------------------------------------------
   73  adbd
18249  android.process.acore
19940  android.process.media
   75  audioserver
...
```

Now, install the LokiBot sample: 

```
root@90b58e6bc8f4:~# adb install lokibot.apk 
Success
```

**Q8**. Find the package name of the Android/Lokibot sample. To list packages on an emulator, use `pm list packages`

We are now going to launch Frida with our hook. The syntax is

```
frida -D emulator-5554 -l yourhook.js -f packagename --no-pause
```

You should see the de-obfuscated strings!

**Troubleshooting Frida:**

- **"Failed to spawn: timeout was reached"**. Check on the Android emulator if the process is launched or not. If not, try again ;-) If it is up, then **attach** (-n) to the process with frida.
- **"Failed to load script: the connection is closed"**. Check that the Frida server is still running. If it is, then try again the command...
- Be sure to  use the same version of Frida client and Frida server (`frida-server --version`). Frida servers can be downloaded from https://github.com/frida/frida/releases/download/VERSION/frida-server-VERSION-android-arm.xz where VERSION is for example 12.2.5.
- Be sure to run Frida server as **root**


### Showing stack

We are going to **improve the hook**. 
Currently, you get de-obfuscated strings, but it's difficult to know *where they are located in the code*.

Example:

```
de-obfuscating: (k7m= to: phone
```

Fortunately, Frida users share some interesting code snippets on [Codeshare Frida](https://codeshare.frida.re/).
We are going to use [this code snippet](https://codeshare.frida.re/@razaina/get-a-stack-trace-in-your-hook/).
It is written by **@razaina**.

```javascript
Java.performNow(function(){
        var target = Java.use("com.pacakge.myClass");
        var threadef = Java.use('java.lang.Thread');
        var threadinstance = threadef.$new();

        function Where(stack){
            var at = "";
            for(var i = 0; i < stack.length; ++i){
                at += stack[i].toString() + "\n";
            }
            return at;
        }

        target.foo.overload("java.lang.String").implementation = function(obfuscated_str){
            var ret = this.foo(obfuscated_str);
            var stack = threadinstance.currentThread().getStackTrace();
            var full_call_stack = Where(stack);
            send("Deobfuscated " + ret + " @ " + stack[3].toString() + "\n\t Full call stack:" + full_call_stack) ;
            return ret;
        }
    })
```

This code snippet works as follows:

1. Declare classes and instances
2. Write a function that displays the stack
3. Dummy hook. Note that `overload` is used to overload a specific function named `foo`. For example, if you have `void foo(int)` and `void foo(String)`, this hook will only hook the latter, `void foo(String)`. If there is only one possible function for a given name, `overload` does not need to be indicated.

**Q9**. Modify your Frida hook to display the stack before each de-obfuscated string.


# Closing remarks

If you have any feedback concerning this training, please [email me](mailto:aapvrille@fortinet.com).

**HAPPY END ?**

