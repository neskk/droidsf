Java.perform(function x() {

  var sysexit = Java.use("java.lang.System");
	sysexit.exit.overload("int").implementation = function(var_0) {
		send("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
	};

});