console.log("[*] Loading Frida script for Android/LokiBot");

// check if Java environment is available
if (Java.available) {
    console.log("[*] Java is available");

    Java.perform(function() {
	var threadef = Java.use('java.lang.Thread');
        var threadinstance = threadef.$new();
	function Where(stack){
            var at = "";
            for(var i = 0; i < stack.length; ++i){
                at += stack[i].toString() + "\n";
            }
            return at;
        }

	// https://codeshare.frida.re/@razaina/get-a-stack-trace-in-your-hook/
	absurdityClass = Java.use("fsdfsdf.gsdsfsf.gjhghjg.lbljhkjblkjblkjblkj.absurdityasfasfasfasfafa");
	absurdityClass.abideasfasfasfasfafa.implementation = function(str) {
	    var deob = this.abideasfasfasfasfafa(str);
	    console.log("decoding: "+str+" --> "+deob);
	    var stack = threadinstance.currentThread().getStackTrace();
	    var full_call_stack = Where(stack);
	    console.log("Call Stack: "+full_call_stack);
	    return deob;
	}
	console.log('[*] loaded hooks');
    });
}
