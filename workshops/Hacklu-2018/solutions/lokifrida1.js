console.log("[*] Loading Frida script for Android/LokiBot");

// check if Java environment is available
if (Java.available) {
    console.log("[*] Java is available");

    Java.perform(function() {
	absurdityClass = Java.use("fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.absurdityasfasfasfasfafa");
	absurdityClass.abideasfasfasfasfafa.implementation = function(str) {
	    var deob = this.abideasfasfasfasfafa(str);
	    console.log("de-obfuscating: "+str+" to: "+deob);
	    return deob;
	}
	console.log('[*] loaded hooks');
    });
}
