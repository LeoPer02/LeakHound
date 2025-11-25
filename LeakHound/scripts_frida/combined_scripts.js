Java.perform(function() {

        ////////////////// SOCKET SCRIPT /////////////////////////////////

        // This is the lowest level one can look at the network traces.
        // The benefit in tracing sockets is that most, if not all, request will pass through the socket
        // and therefore we won't miss any of them. However, by attaching to the socker we won't be able to look at the
        // contents, which could otherwise be used to track the requests against mitm. To increase the certainty, mitm should
        // also provide the source port. The chances of 2 different request being sent to the same host, with the same src port which, in theory,
        // is assigned randomly, is quite low, but it could happen. Another possible metric is the use of timestamps, however, for our purposes,
        // we believe using host+port should suffice.

        let LocationManager;
        let FusedLocationProviderClient;
        let Location;
        let Thread;
        let sock;
        let Exception;
        let Log;
        let ContentResolver;
        let Cursor;
        try {
            Thread = Java.use('java.lang.Thread');
        } catch (err) {}
        try{
            Exception = Java.use('java.lang.Exception');
        } catch (err) {}
        try{
            Log = Java.use('android.util.Log');
        } catch (err) {}
        try{
            sock = Java.use("java.net.Socket");
        } catch (err) {}
        try {
            LocationManager = Java.use("android.location.LocationManager");
        } catch (err) {}
        try {
            FusedLocationProviderClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
        } catch (err) {}
        try {
            Location = Java.use("android.location.Location");
        } catch (err) {}
        try {
            ContentResolver = Java.use("android.content.ContentResolver");
            Cursor = Java.use("android.database.Cursor");
        } catch (err) {}


        var androidVersion = parseInt(Java.androidVersion, 10)
        var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com"
        ];
        var RootBinaries = ["mu", ".su", "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk"];
        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1"
        };
        var RootPropertiesKeys = [];
        for (var k in RootProperties) RootPropertiesKeys.push(k);

		// Socket.connect(endPoint)
		try {
		    sock.connect.overload("java.net.SocketAddress").implementation = function(endPoint){
                sock.connect.overload("java.net.SocketAddress").call(this, endPoint);

                // Call it before so that it attaches to a port, if the port is -1 it means it wasn't binded yet
                var callStack = stackTraceHere();

                var threadName = "NONE";
                var threadId = -1;
                var threadGroup = "NONE";
                try {
                    threadName = Thread.currentThread().getName();
                    threadId = Thread.currentThread().getId();
                    threadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var port = this.getLocalPort();
                var endpoint = endPoint.toString();
                var socket = this.getLocalSocketAddress().toString();
                var currentTime = Date.now(); // Epoch time in milliseconds

                currentTime = currentTime / 1000;

                var socketInfo = {
                    script: "socket",
                    msg: {
                        host: endpoint,
                        port: port,
                        timestamp: currentTime,
                        socket: socket,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                }
                send(socketInfo);
		    }
		} catch (err) {}

		try {
            // Socket.connect(endPoint, timeout)
		    sock.connect.overload("java.net.SocketAddress", "int").implementation = function(endPoint, tmout){
                sock.connect.overload("java.net.SocketAddress", "int").call(this, endPoint, tmout);

                // Call it before so that it attaches to a port, if the port is -1 it means it wasn't binded yet
                var callStack = stackTraceHere();

                var threadName = "NONE";
                var threadId = -1;
                var threadGroup = "NONE";
                try {
                    threadName = Thread.currentThread().getName();
                    threadId = Thread.currentThread().getId();
                    threadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var port = this.getLocalPort();
                var endpoint = endPoint.toString();
                var socket = this.getLocalSocketAddress().toString();
                var currentTime = Date.now(); // Epoch time in milliseconds

                currentTime = currentTime / 1000;

                var socketInfo = {
                    script: "socket",
                    msg: {
                        host: endpoint,
                        port: port,
                        timestamp: currentTime,
                        socket: socket,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                }
                send(socketInfo);

            }
		} catch (err) {}

		//////////////////// END OF SOCKET SCRIPT //////////////////


		//////////////////// THREAD SCRIPT /////////////////////////


        // These frida hooks will retrieve the callstack on memory the moment a thread is created
        // This can be used to complete the callstack of other calls.
        // Take for example a snippet which creates a thread to send a network request:
        //
        //
        //            public class NetworkRequestRunnable implements Runnable {
        //                @Override
        //                public void run() {
        //                    // Initialize OkHttpClient
        //                    OkHttpClient client = new OkHttpClient();
        //
        //                    // Build the request
        //                    Request request = new Request.Builder()
        //                        .url("https://example.com/api")
        //                        .build();
        //
        //                    // Execute the request
        //                    try (Response response = client.newCall(request).execute()) {
        //                        if (response.isSuccessful()) {
        //                            // Handle the response
        //                            System.out.println(response.body().string());
        //                        } else {
        //                            // Handle the error
        //                            System.err.println("Request failed: " + response);
        //                        }
        //                    } catch (IOException e) {
        //                        e.printStackTrace();
        //                    }
        //                }
        //
        //                public static void main(String[] args) {
        //                    // Create a new thread to execute the network request
        //                    Thread networkThread = new Thread(new NetworkRequestRunnable());
        //                    networkThread.start();
        //                }
        //            }
        //
        // In this scenario, attempting to retrieve the callstack with frida at the network request `client.newCall(request).execute()` will return only
        // the call stack up until the Thread.run() call. Since the callstacks from the main thread are separated from the new thread's callstack, the
        // information we will be able to retrieve will be small, unless the app does not use Threads before the sinks.
        // However, with this hook we can check the callstack when a new Thread object is initialized. By hooking this function we can initialize the object ourselves
        // retrieve the thread name, the callstack at the time of the object initialization and return the object so that the program can continue.
        // Later, once we're analyzing a callstack from another hook, if the callstack stops at a Thread.run() we can (assuming the script sends the thread name)
        // look at the data provided by this script, and reconstruct the path. In theory, this also supports nested Threads (so a thread being created inside of a
        // thread), although, this seems quite unusual, specially with depths longer than 3.

        try {
            // Hook constructor: Thread()
            Thread.$init.overload().implementation = function() {
                //console.log('Thread created using Thread() constructor');
                var thread = this.$init();
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}

        try {
            // Hook constructor: Thread(Runnable target)
            Thread.$init.overload('java.lang.Runnable').implementation = function(target) {
                //console.log('Thread created using Thread(Runnable) constructor');
                var thread = this.$init(target);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}

        try {
            // Hook constructor: Thread(Runnable target, String name)
            Thread.$init.overload('java.lang.Runnable', 'java.lang.String').implementation = function(target, name) {
                //console.log('Thread created using Thread(Runnable, String) constructor');
                var thread = this.$init(target, name);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}


        try {
            // Hook constructor: Thread(String name)
            Thread.$init.overload('java.lang.String').implementation = function(name) {
                //console.log('Thread created using Thread(String) constructor');
                var thread = this.$init(name);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}

        try {
            // Hook constructor: Thread(ThreadGroup group, Runnable target)
            Thread.$init.overload('java.lang.ThreadGroup', 'java.lang.Runnable').implementation = function(group, target) {
                //console.log('Thread created using Thread(ThreadGroup, Runnable) constructor');
                var thread = this.$init(group, target);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}

        try {
            // Hook constructor: Thread(ThreadGroup group, String name)
            Thread.$init.overload('java.lang.ThreadGroup', 'java.lang.String').implementation = function(group, name) {
                //console.log('Thread created using Thread(ThreadGroup, String) constructor');
                var thread = this.$init(group, name);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}


        try {
            // Hook constructor: Thread(ThreadGroup group, Runnable target, String name)
            Thread.$init.overload('java.lang.ThreadGroup', 'java.lang.Runnable', 'java.lang.String').implementation = function(group, target, name) {
                //console.log('Thread created using Thread(ThreadGroup, Runnable, String) constructor');
                var thread = this.$init(group, target, name);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}


        try {
            // Hook constructor: Thread(ThreadGroup group, Runnable target, String name, long stackSize)
            Thread.$init.overload('java.lang.ThreadGroup', 'java.lang.Runnable', 'java.lang.String', 'long').implementation = function(group, target, name, stackSize) {
                //console.log('Thread created using Thread(ThreadGroup, Runnable, String, long) constructor');
                var thread = this.$init(group, target, name, stackSize);
                var threadName = this.getName();
                var threadId = this.getId();
                var threadGroup = this.getThreadGroup().getName();
                var callStack = stackTraceHere();

                // Try to extract the parent thread information, if one exists
                var ParentThreadName = "NONE";
                var ParentThreadId = -1;
                var ParentThreadGroup = "NONE";
                try {
                    ParentThreadName = Thread.currentThread().getName();
                    ParentThreadId = Thread.currentThread().getId();
                    ParentThreadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}

                var threadData = {
                    script: "thread",
                    msg: {
                        parent_thread_name: ParentThreadName,
                        parent_thread_id: ParentThreadId,
                        parent_thread_group: ParentThreadGroup,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };
                send(threadData)
                return thread;
            };
        } catch (err) {}

		////////////////// END OF THREAD SCRIPT /////////////////////////////////


		///////////////////// LOCATION SCRIPT /////////////////////////////////

		try {
		    // Hook getLastKnownLocation
            LocationManager.getLastKnownLocation.overload("java.lang.String").implementation = function (provider) {
                var result = this.getLastKnownLocation(provider);
                if (result !== null) {
                    var threadName = "NONE";
                    var threadId = -1;
                    var threadGroup = "NONE";
                    try {
                        threadName = Thread.currentThread().getName();
                        threadId = Thread.currentThread().getId();
                        threadGroup = Thread.currentThread().getThreadGroup().getName();
                    } catch (err) {}
                    sendLocationData("getLastKnownLocation", provider, result.getLatitude(), result.getLongitude(), threadName, threadId, threadGroup);
                }
                return result;
            };
		} catch (err) {}

        try {
            // Hook FusedLocationProviderClient.getLastLocation()
            FusedLocationProviderClient.getLastLocation.overload().implementation = function () {
                var result = this.getLastLocation();
                result.then(function (location) {
                    if (location !== null) {
                        var threadName = "NONE";
                        var threadId = -1;
                        var threadGroup = "NONE";
                        try {
                            threadName = Thread.currentThread().getName();
                            threadId = Thread.currentThread().getId();
                            threadGroup = Thread.currentThread().getThreadGroup().getName();
                        } catch (err) {}
                        sendLocationData("getLastLocation", null, location.getLatitude(), location.getLongitude(), threadName, threadId, threadGroup);
                    }
                });
                return result;
            };
		} catch (err) {}

        try {
            FusedLocationProviderClient.getLastLocation.overload('com.google.android.gms.location.LastLocationRequest').implementation = function (request) {
                var result = this.getLastLocation(request)
                result.then(function (location) {
                    if (location !== null) {
                        var threadName = "NONE";
                        var threadId = -1;
                        var threadGroup = "NONE";
                        try {
                            threadName = Thread.currentThread().getName();
                            threadId = Thread.currentThread().getId();
                            threadGroup = Thread.currentThread().getThreadGroup().getName();
                        } catch (err) {}
                        sendLocationData("getLastLocation", null, location.getLatitude(), location.getLongitude(), threadName, threadId, threadGroup);
                    }
                });
                return result;
            };
		} catch (err) {}

        try {
            // Hook getLatitude and getLongitude
            Location.getLatitude.implementation = function () {
                var latitude = this.getLatitude();
                var threadName = "NONE";
                var threadId = -1;
                var threadGroup = "NONE";
                try {
                    threadName = Thread.currentThread().getName();
                    threadId = Thread.currentThread().getId();
                    threadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}
                sendLocationData("getLatitude", null, latitude, null, threadName, threadId, threadGroup);
                return latitude;
            };
		} catch (err) {}


        try {
            Location.getLongitude.implementation = function () {
                var longitude = this.getLongitude();
                var threadName = "NONE";
                var threadId = -1;
                var threadGroup = "NONE";
                try {
                    threadName = Thread.currentThread().getName();
                    threadId = Thread.currentThread().getId();
                    threadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}
                sendLocationData("getLongitude", null, null, longitude, threadName, threadId, threadGroup);
                return longitude;
            };
		} catch (err) {}


		///////////////////// END OF LOCATION SCRIPT /////////////////////////////////


		///////////////////// CONTENT QUERY SCRIPT /////////////////////////////////


		try {
            ContentResolver.query.overload(
                "android.net.Uri",
                "[Ljava.lang.String;",
                "java.lang.String",
                "[Ljava.lang.String;",
                "java.lang.String"
            ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
                //console.log("\n[+] Contacts Access Detected!");
                var URI = uri.toString();
                //console.log("URI: " + URI);

                //if (projection) console.log("Projection: " + JSON.stringify(projection));
                //if (selection) console.log("Selection: " + selection);
                //if (selectionArgs) console.log("Selection Args: " + JSON.stringify(selectionArgs));
                //if (sortOrder) console.log("Sort Order: " + sortOrder);

                var cursor = this.query(uri, projection, selection, selectionArgs, sortOrder);
                //console.log("[+] Query executed. Hooking Cursor...");

                if (cursor) {
                    var callStack = stackTraceHere();
                    var threadName = "NONE";
                    var threadId = -1;
                    var threadGroup = "NONE";
                    try {
                        threadName = Thread.currentThread().getName();
                        threadId = Thread.currentThread().getId();
                        threadGroup = Thread.currentThread().getThreadGroup().getName();
                    } catch (err) {}
                    //console.log("Callstack: " + callStack);
                    getCursorContents(cursor, callStack, URI, threadName, threadId, threadGroup); // No deep copy needed here
                } else {
                    //console.log("[-] Cursor is NULL!");
                }

                // We call the function twice since by iteration through the cursor object will change it's state
                // This can be circunvented by calling:
                //      cursor.moveToFirst();
                //      cursor.moveToPrevious();
                // after the while cycle to return it to the beggining. However, getting the result again is a safer approach
                // If for some reason you need to send the first object (maybe changes were applied) then use the instructions mentioned above
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };

        } catch (err) {}


        function getCursorContents(cursor, callStack, URI, threadName, threadId, threadGroup) {
            try {
                var columnCount = cursor.getColumnCount();
                //console.log("[+] Column Count: " + columnCount);

                var columns = [];
                for (var i = 0; i < columnCount; i++) {
                    columns.push(cursor.getColumnName(i));
                }
                //console.log("[+] Column Names: " + JSON.stringify(columns));

                var allData = []; // Array to accumulate all the row data

                while (cursor.moveToNext()) {
                    try {
                        //console.log("[+] Moving to next contact...");
                        var rowData = {};
                        for (var i = 0; i < columnCount; i++) {
                            rowData[columns[i]] = cursor.getString(i);
                        }
                        //console.log("[+] Contact Data: " + JSON.stringify(rowData));

                        // Add rowData to the allData array
                        if (Object.keys(rowData).length !== 0) {
                            allData.push(rowData);
                        }

                    } catch (err) {
                        //console.log("[-] Error accessing row data: " + err);
                    }
                }

                // If there is any data, send the request with all entries
                if (allData.length > 0) {
                    var requestData = {
                        script: "content_query",
                        msg: {
                            uri: URI,
                            data: allData, // Send all accumulated row data
                            thread_name: threadName,
                            thread_id: threadId,
                            thread_group: threadGroup,
                            callStack: callStack // Include the call stack
                        }
                    };
                    send(requestData);
                } else {
                    //console.log("[-] No valid contact data found.");
                }

            } catch (err) {
                //console.log("[-] Error iterating Cursor: " + err);
            }
        }


		///////////////////// END OF CONTENT QUERY SCRIPT /////////////////////////////////


		///////////////////// SSL-BYPASS SCRIPT /////////////////////////////////


        // From MobSF
        // Slightly modified
        Java.perform(function() {
            var androidVersion = parseInt(Java.androidVersion, 10)
            if (androidVersion > 6){
                try{
                    // Generic SSL Pinning Bypass tested on Android 7, 7.1, 8, and 9
                    // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/platform/java/org/conscrypt/TrustManagerImpl.java#391
                    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                    TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrustedChain, trustedChain, used) {
                        send('[SSL Pinning Bypass] checkTrustedRecursive() bypassed');
                        return Java.use('java.util.ArrayList').$new();
                    }
                }catch (err) {
                    send('[SSL Pinning Bypass] TrustManagerImpl.checkTrustedRecursive() not found');
                }
                try {
                    var TrustManagerImpl2 = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                    TrustManagerImpl2.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                        send('[SSL Pinning Bypass] verifyChain() bypassed for: ' + host);
                        return untrustedChain;
                    }
                } catch (err) {
                    send('[SSL Pinning Bypass] TrustManagerImpl.verifyChain() not found');
                }
                try {
                    var ConscryptFileDescriptorSocket = Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket');
                    ConscryptFileDescriptorSocket.verifyCertificateChain.implementation = function (certChain, authMethod) {
                        send('[SSL Pinning Bypass] verifyCertificateChain() bypassed');
                        return;
                    }
                } catch (err) {
                    send('[SSL Pinning Bypass] ConscryptFileDescriptorSocket.verifyCertificateChain() not found');
                }
            } else if (androidVersion > 4 && androidVersion < 7) {
                // Generic SSL Pinning Bypass tested on Android 5, 5,1, 6
                // https://codeshare.frida.re/@akabe1/frida-universal-pinning-bypasser/
                try {
                    var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                    OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
                        send('[SSL Pinning Bypass] OpenSSLSocketImpl.verifyCertificateChain() bypassed');
                        return;
                    }
                } catch (err) {
                    send('[SSL Pinning Bypass] OpenSSLSocketImpl.verifyCertificateChain() not found');
                }
            }
            // 3rd Party Pinning
            try{
        //        var OkHttpClient = Java.use('com.squareup.okhttp.OkHttpClient');
        //        OkHttpClient.setCertificatePinner.implementation = function(certificatePinner){
        //            send('[SSL Pinning Bypass] OkHttpClient.setCertificatePinner() bypassed');
        //            return this;
        //        };
        //        // Invalidate the certificate pinnet checks (if 'setCertificatePinner' was called before the previous invalidation)
        //        var CertificatePinner = Java.use('com.squareup.okhttp.CertificatePinner');
        //        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1){
        //            send('[SSL Pinning Bypass] CertificatePinner.check() 1 bypassed');
        //            return;
        //        };
        //        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1){
        //            send('[SSL Pinning Bypass] CertificatePinner.check() 2 bypassed');
        //            return;
        //        };

                /////////////////// OKHTTP SSL PINNING BYPASS FROM: https://codeshare.frida.re/@federicodotta/okhttp3-pinning-bypass/ //////////////////////////////////////


                var okhttp3_CertificatePinner_class = null;
                try {
                    okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');
                } catch (err) {
                    //console.log('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
                    okhttp3_CertificatePinner_class = null;
                }

                if(okhttp3_CertificatePinner_class != null) {

                        try{
                            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str,list) {
                                //console.log('[+] Bypassing OkHTTPv3 1: ' + str);
                                return true;
                            };
                            //console.log('[+] Loaded OkHTTPv3 hook 1');
                        } catch(err) {
                            //console.log('[-] Skipping OkHTTPv3 hook 1');
                        }

                        try{
                            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str,cert) {
                                //console.log('[+] Bypassing OkHTTPv3 2: ' + str);
                                return true;
                            };
                            //console.log('[+] Loaded OkHTTPv3 hook 2');
                        } catch(err) {
                            //console.log('[-] Skipping OkHTTPv3 hook 2');
                        }

                        try {
                            okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str,cert_array) {
                                //console.log('[+] Bypassing OkHTTPv3 3: ' + str);
                                return true;
                            };
                            //console.log('[+] Loaded OkHTTPv3 hook 3');
                        } catch(err) {
                            //console.log('[-] Skipping OkHTTPv3 hook 3');
                        }

                        try {
                            okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str,obj) {
                                //console.log('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
                            };
                            //console.log('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
                        } catch(err) {
                            //console.log('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
                        }

                    }

            } catch(err) {
                send('[SSL Pinning Bypass] okhttp CertificatePinner not found');
            }
            try {
                var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
                CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
                    send('[SSL Pinning Bypass] okhttp3.CertificatePinner.check() bypassed for ' + str);
                    return;
                };
            } catch(err) {
                send('[SSL Pinning Bypass] okhttp3 CertificatePinner not found');
            }
            try {
                // https://gist.github.com/cubehouse/56797147b5cb22768b500f25d3888a22
                var dataTheorem = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
                dataTheorem.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                    send('[SSL Pinning Bypass] DataTheorem trustkit.pinning.OkHostnameVerifier.verify() 1 bypassed for ' + str);
                    return true;
                };

                dataTheorem.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                    send('[SSL Pinning Bypass] DataTheorem trustkit.pinning.OkHostnameVerifier.verify() 2 bypassed for ' + str);
                    return true;
                };
            } catch(err) {
                send('[SSL Pinning Bypass] DataTheorem trustkit not found');
            }
            try {
                var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
                PinningTrustManager.checkServerTrusted.implementation = function () {
                    send('[SSL Pinning Bypass] Appcelerator appcelerator.https.PinningTrustManager.checkServerTrusted() bypassed');
                }
            } catch (err) {
               send('[SSL Pinning Bypass] Appcelerator PinningTrustManager not found');
            }
            try {
                var SSLCertificateChecker = Java.use('nl.xservices.plugins.SSLCertificateChecker');
                SSLCertificateChecker.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (action, args, callbackContext) {
                    send('[SSL Pinning Bypass] Apache Cordova - SSLCertificateChecker.execute() bypassed');
                    callbackContext.success('CONNECTION_SECURE');
                    return;
                };
            } catch(err) {
                send('[SSL Pinning Bypass] Apache Cordova SSLCertificateChecker not found');
            }
            try {
                var wultra = Java.use('com.wultra.android.sslpinning.CertStore');
                wultra.validateFingerprint.overload('java.lang.String', '[B').implementation = function (commonName, fingerprint) {
                    send('[SSL Pinning Bypass] Wultra com.wultra.android.sslpinning.CertStore.validateFingerprint() bypassed');
                    var ValidationResult = Java.use('com.wultra.android.sslpinning.ValidationResult');
                    return ValidationResult.TRUSTED;
                };
            } catch(err) {
                send('[SSL Pinning Bypass] Wultra CertStore.validateFingerprint not found');
            }

            /* Based on https://blog.csdn.net/ALakers/article/details/107642166
            WebView SSL Error Bypass */
            try {
                var WebViewClient = Java.use('android.webkit.WebViewClient');
                WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                    send('WebViewClient onReceivedSslError bypassed');
                    sslErrorHandler.proceed();
                    return;
                };
                WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(a, b, c, d) {
                    send('WebViewClient onReceivedError bypassed');
                    return;
                };
                WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function() {
                    send('WebViewClient onReceivedError bypassed');
                    return;
                };
            } catch(err) {
                send('[SSL Pinning Bypass] WebViewClient not found');
            }
            /*** HttpsURLConnection ***/
            try {
                var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                /*
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                    send('[SSL Pinning Bypass] HttpsURLConnection.setDefaultHostnameVerifier bypassed');
                    return null;
                };*/
                HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
                    send('[SSL Pinning Bypass] HttpsURLConnection.setSSLSocketFactory bypassed');
                    return null;
                };
                HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                    send('[SSL Pinning Bypass] HttpsURLConnection.setHostnameVerifier bypassed');
                    return null;
                };
            } catch(err) {
                send('[SSL Pinning Bypass] HttpsURLConnection not found');
            }
            try {
                /* SSLContext */
                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                var TrustManager;
                try {
                    TrustManager = Java.registerClass({
                        name: 'fake.TrustManager',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function(chain, authType) {},
                            checkServerTrusted: function(chain, authType) {},
                            getAcceptedIssuers: function() {
                                return [];
                            }
                        }
                    });
                } catch (e) {
                }

                var EmptySSLFactory;
                try {
                    var TrustManagers = [TrustManager.$new()];
                    var TLS_SSLContext = SSLContext.getInstance('TLS');
                    TLS_SSLContext.init(null, TrustManagers, null);
                    EmptySSLFactory = TLS_SSLContext.getSocketFactory();

                    var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
                    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                        SSLContext_init.call(this, null, TrustManagers, null);
                        // send('[SSL Pinning Bypass] SSLContext.init() bypass');
                    };
                } catch (e) {
                    send('[SSL Pinning Bypass] SSLContext.init() not found');
                }
                /* Xutils */
                var TrustHostnameVerifier;
                try {
                    TrustHostnameVerifier = Java.registerClass({
                        name: 'fake.TrustHostnameVerifier',
                        implements: [HostnameVerifier],
                        method: {
                            verify: function(hostname, session) {
                                return true;
                            }
                        }
                    });
                } catch (e) {
                }
                var RequestParams = Java.use('org.xutils.http.RequestParams');
                RequestParams.setSslSocketFactory.implementation = function(sslSocketFactory) {
                    sslSocketFactory = EmptySSLFactory;
                    return null;
                }
                RequestParams.setHostnameVerifier.implementation = function(hostnameVerifier) {
                    hostnameVerifier = TrustHostnameVerifier.$new();
                    return null;
                }
            } catch (e) {
                send('[SSL Pinning Bypass] Xutils not found');
            }
            /* httpclientandroidlib */
            try {
                var AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
                AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function() {
                    send('[SSL Pinning Bypass] httpclientandroidlib AbstractVerifier bypassed');
                    return null;
                }
            } catch (e) {
                send('[SSL Pinning Bypass] httpclientandroidlib not found');
            }
            /* cronet */
            try {
                var netBuilder = Java.use('org.chromium.net.CronetEngine$Builder');
                netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function(arg) {
                    var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                    return ret;
                };
                netBuilder.addPublicKeyPins.implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
                    return this;
                };
                send('[SSL Pinning Bypass] Cronet Public Key pinning bypassed');
            } catch (err) {
                send('[SSL Pinning Bypass] Cronet not found');
            }
            /* Boye AbstractVerifier */
            try {
                Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier").verify.implementation = function(host, ssl) {
                send("[SSL Pinning Bypass] Bypassing Boye AbstractVerifier" + host);
            };
            } catch (err) {
                send("[SSL Pinning Bypass] Boye AbstractVerifier not found");
            }
            /* Appmattus */
            try {
                /* Certificate Transparency Bypass Ajin Abraham - opensecurity.in */
                Java.use('com.babylon.certificatetransparency.CTInterceptorBuilder').includeHost.overload('java.lang.String').implementation = function(host) {
                    send('[SSL Pinning Bypass] Bypassing Certificate Transparency check');
                    return this.includeHost('nonexistent.domain');
                };
            } catch (err) {
                send('[SSL Pinning Bypass] babylon certificatetransparency.CTInterceptorBuilder not found');
            }
            try {
                Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor")["intercept"].implementation = function(a) {
                    send("[SSL Pinning Bypass] Appmattus Certificate Transparency");
                    return a.proceed(a.request());
                };
            } catch (err) {
                send("[SSL Pinning Bypass] Appmattus CertificateTransparencyInterceptor not found");
            }
            try{
                bypassOkHttp3CertificateTransparency();
            } catch (err) {
                send('[SSL Pinning Bypass] certificatetransparency.CTInterceptorBuilder not found');
            }
        }, 0);


        function bypassOkHttp3CertificateTransparency() {
          // https://gist.github.com/m-rey/f2a235123908ca42395b6d3c5fe1128e
          try{
            var CertificateTransparencyInterceptor = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor');
            var OkHttpClientBuilder = Java.use('okhttp3.OkHttpClient$Builder');

            CertificateTransparencyInterceptor.intercept.implementation = function (chain) {
                var request = chain.request();
                var url = request.url();
                var host = url.host();

                // Dynamically access the VerificationResult classes
                var VerificationResult = Java.use('com.appmattus.certificatetransparency.VerificationResult');
                var VerificationResultSuccessInsecureConnection = Java.use('com.appmattus.certificatetransparency.VerificationResult$Success$InsecureConnection');
                var VerificationResultFailureNoCertificates = Java.use('com.appmattus.certificatetransparency.VerificationResult$Failure$NoCertificates');

                // Create instances of the desired VerificationResult classes
                var success = VerificationResultSuccessInsecureConnection.$new(host);
                var failureNoCertificates = VerificationResultFailureNoCertificates.$new();

                // Bypass certificate transparency verification
                var certs = chain.connection().handshake().peerCertificates();
                if (certs.length === 0) {
                send('[SSL Pinning Bypass] Certificate transparency bypassed.');
                return failureNoCertificates;
                }

                try {
                // Proceed with the original request
                return chain.proceed(request);
                } catch (e) {
                // Catch SSLPeerUnverifiedException and return intercepted response
                if (e.toString().includes('SSLPeerUnverifiedException')) {
                    send('[SSL Pinning Bypass] Certificate transparency failed.');
                    return failureNoCertificates;
                }
                throw e;
                }
            };

            OkHttpClientBuilder.build.implementation = function () {
                // Intercept the OkHttpClient creation
                var client = this.build();
                return client;
            };
          } catch (err) {}
        }


		///////////////////// END OF SSL-BYPASS SCRIPT /////////////////////////////////



		///////////////////// ROOT-BYPASS SCRIPT /////////////////////////////////


		try {
            var NativeFile = Java.use('java.io.File');
            NativeFile.exists.implementation = function () {
                var name = NativeFile.getName.call(this);
                if (RootBinaries.indexOf(name) > -1) {
                    send("[RootDetection Bypass] return value for binary: " + name);
                    return false;
                } else {
                    return this.exists.call(this);
                }
            };
        } catch (err) {}
        // File.exists check

        try {
            // String.contains check
            var javaString = Java.use('java.lang.String');
            javaString.contains.implementation = function (name) {
                if (name == "test-keys") {
                    send("[RootDetection Bypass] test-keys check");
                    return false;
                }
                return this.contains.call(this, name);
            };
        } catch (err) {}

        try {
             var Runtime = Java.use('java.lang.Runtime');
            var execImplementations = get_implementations(Runtime.exec)
            var exec = Runtime.exec.overload('java.lang.String')

            execImplementations.forEach(function (args, _) {
                Runtime.exec.overload.apply(null, args).implementation = function () {
                    var fakeCmd;
                    var argz = [].slice.call(arguments);
                    var cmd = argz[0];
                    if (typeof cmd === 'string') {
                        fakeCmd = isRootCheck(cmd);
                        if (fakeCmd) {
                            send("[RootDetection Bypass] " + cmd + " command");
                            return exec.call(this, fakeCmd);
                        }
                    } else if (typeof cmd === 'object') {
                        for (var i = 0; i < cmd.length; i = i + 1) {
                            var tmp_cmd = cmd[i];
                            fakeCmd = isRootCheck(tmp_cmd);
                            if (fakeCmd) {
                                send("[RootDetection Bypass] " + cmd + " command");
                                return exec.call(this, '');
                            }
                        }
                    }
                    return this['exec'].apply(this, argz);
                };
            });
        } catch (err) {}


         try {
             // BufferedReader checkLine check
            var BufferedReader = Java.use('java.io.BufferedReader');
            BufferedReader.readLine.overload().implementation = function () {
                var text = this.readLine.call(this);
                if (text === null) {
                    // just pass , i know it's ugly as hell but test != null won't work :(
                } else {
                    var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                    if (shouldFakeRead) {
                        send("[RootDetection Bypass] build.prop file read");
                        text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }
                }
                return text;
            }
        } catch (err) {}

         try {
            var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            ProcessBuilder.start.implementation = function () {
                var cmd = this.command.call(this);
                var shouldModifyCommand = false;
                for (var i = 0; i < cmd.size(); i = i + 1) {
                    var tmp_cmd = cmd.get(i).toString();
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                        shouldModifyCommand = true;
                    }
                }
                if (shouldModifyCommand) {
                    send("[RootDetection Bypass] ProcessBuilder " + JSON.stringify(cmd));
                    this.command.call(this, ["grep"]);
                    return this.start.call(this);
                }
                if (cmd.indexOf("su") != -1) {
                    send("[RootDetection Bypass] ProcessBuilder " + JSON.stringify(cmd));
                    this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
                    return this.start.call(this);
                }

                return this.start.call(this);
            }
        } catch (err) {}
        // ProcessBuilder.start check


        // Patch other libraries after the above ones
        var toHook, className, classMethod;
        try {
            className = 'android.app.ApplicationPackageManager'
            classMethod = 'getPackageInfo'
            toHook = Java.use(className)[classMethod];
            if (!toHook) {
                send('[RootDetection Bypass] Cannot find ' + className + '.' + classMethod);
                return
            }
            toHook.overload('java.lang.String', 'int').implementation = function (pname, flags) {
                var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
                if (shouldFakePackage) {
                    send("[RootDetection Bypass] root check for package: " + pname);
                    pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
                }
                return this.getPackageInfo.call(this, pname, flags);
            }
        } catch (err) {
            send('[RootDetection Bypass] Error ' + className + '.' + classMethod + err);
        }

        try {
            className = 'android.os.SystemProperties'
            classMethod = 'get'
            toHook = Java.use(className)[classMethod];
            if (!toHook) {
                send('[RootDetection Bypass] Cannot find ' + className + '.' + classMethod);
                return
            }
            toHook.overload('java.lang.String').implementation = function (name) {
                if (RootPropertiesKeys.indexOf(name) != -1) {
                    send("[RootDetection Bypass] " + name);
                    return RootProperties[name];
                }
                return this.get.call(this, name);
            }
        } catch (err) {
            send('[RootDetection Bypass] Error ' + className + '.' + classMethod + err);
        }
        try {
            className = 'android.security.keystore.KeyInfo'
            classMethod = 'isInsideSecureHardware'
            if (parseInt(Java.androidVersion, 10) < 6) {
                send('[RootDetection Bypass] Not Hooking unavailable class/classMethod - ' + className + '.' + classMethod)
                return
            }
            toHook = Java.use(className)[classMethod];
            if (!toHook) {
                send('[RootDetection Bypass] Cannot find ' + className + '.' + classMethod);
                return
            }
            toHook.implementation = function () {
                send("[RootDetection Bypass] isInsideSecureHardware");
                return true;
            }
        } catch (err) {
            send('[RootDetection Bypass] Error ' + className + '.' + classMethod + err);
        }

        // Native Root Check Bypass

         try {
             Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
                onEnter: function (args) {
                    var path = Memory.readCString(args[0]);
                    path = path.split("/");
                    var executable = path[path.length - 1];
                    var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                    if (shouldFakeReturn) {
                        Memory.writeUtf8String(args[0], "/notexists");
                        send("[RootDetection Bypass] native fopen");
                    }
                },
                onLeave: function (retval) {

                }
            });
        } catch (err) {}

         try {
                Interceptor.attach(Module.findExportByName("libc.so", "system"), {
                    onEnter: function (args) {
                        var cmd = Memory.readCString(args[0]);
                        send("[RootDetection Bypass] SYSTEM CMD: " + cmd);
                        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                            send("[RootDetection Bypass] native system: " + cmd);
                            Memory.writeUtf8String(args[0], "grep");
                        }
                        if (cmd == "su") {
                            send("[RootDetection Bypass] native system: " + cmd);
                            Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                        }
                    },
                    onLeave: function (retval) {

                    }

                });
        } catch (err) {}

        // Bypassing Root in React Native JailMonkey
        // Source: https://codeshare.frida.re/@RohindhR/react-native-jail-monkey-bypass-all-checks/
        try {
            let toHook = Java.use('com.gantix.JailMonkey.JailMonkeyModule')['getConstants'];
            toHook.implementation = function() {
                var hashmap = this.getConstants();
                hashmap.put('isJailBroken', Java.use("java.lang.Boolean").$new(false));
                hashmap.put('hookDetected', Java.use("java.lang.Boolean").$new(false));
                hashmap.put('canMockLocation', Java.use("java.lang.Boolean").$new(false));
                hashmap.put('isOnExternalStorage', Java.use("java.lang.Boolean").$new(false));
                hashmap.put('AdbEnabled', Java.use("java.lang.Boolean").$new(false));
                return hashmap;
            }
        } catch (err) {}
        try{
            // Bypassing Rooted Check
            let hook = Java.use('com.gantix.JailMonkey.Rooted.RootedCheck')['getResultByDetectionMethod']
            hook.implementation = function() {
                let map = this.getResultByDetectionMethod();
                map.put("jailMonkey", Java.use("java.lang.Boolean").$new(false));
                return map;
            }

        } catch (err) {}
        try{
            // Bypassing Root detection method's result of RootBeer library
            var className = 'com.gantix.JailMonkey.Rooted.RootedCheck$RootBeerResults';
            let toHook = Java.use(className)['isJailBroken'];
            toHook.implementation = function() {
                return false;
            };

            let toHook2 = Java.use(className)['toNativeMap']
            toHook2.implementation = function() {
                var map = this.toNativeMap.call(this);
                map.put("detectRootManagementApps", Java.use("java.lang.Boolean").$new(false));
                map.put("detectPotentiallyDangerousApps", Java.use("java.lang.Boolean").$new(false));
                map.put("checkForSuBinary", Java.use("java.lang.Boolean").$new(false));
                map.put("checkForDangerousProps", Java.use("java.lang.Boolean").$new(false));
                map.put("checkForRWPaths", Java.use("java.lang.Boolean").$new(false));
                map.put("detectTestKeys", Java.use("java.lang.Boolean").$new(false));
                map.put("checkSuExists", Java.use("java.lang.Boolean").$new(false));
                map.put("checkForRootNative", Java.use("java.lang.Boolean").$new(false));
                map.put("checkForMagiskBinary", Java.use("java.lang.Boolean").$new(false));
                return map;
            };
        } catch (err) {}


		///////////////////// END OF ROOT-BYPASS SCRIPT /////////////////////////////////


		////////////////// UTIL SCRIPTS /////////////////////////////////

		// Trigger an exception to get the call stack
        function stackTraceHere() {
            var callStack = [];
            try {
                var triggeredException = Log.getStackTraceString(Exception.$new());
                callStack = extractMethods(triggeredException);
            } catch (error) {
                //console.log("[Error] Failed to capture stack trace: " + error);
            }
            return callStack;
        }

        // Extract method names from the stack trace
        function extractMethods(stackTrace) {
            var methods = [];
            try {
                // Split stack trace by new lines
                var lines = stackTrace.trim().split("\n");
                lines.forEach(function(line) {
                    var methodMatch = line.match(/at ([\w\.\$]+(?:\([\w\.\$]+(?:\:[\d]+)?\))?)/);
                    if (methodMatch) {
                        methods.push(methodMatch[1]);
                    }
                });
            } catch (error) {
                //console.log("[Error] Failed to extract methods from stack trace: " + error);
            }
            return methods;
        }

        function getStackTrace() {
            var stackTrace = Log.getStackTraceString(Exception.$new()).trim().split("\n");
            var methods = stackTrace.map(line => {
                var match = line.match(/at ([\w\.\$]+(?:\([\w\.\$]+(?:\:[\d]+)?\))?)/);
                return match ? match[1] : null;
            }).filter(Boolean);
            return methods;
        }

        function getTimestamp() {
            return Math.floor(new Date().getTime() / 1000); // Unix timestamp (seconds)
        }

        function sendLocationData(method, provider, latitude, longitude, threadName, threadId, threadGroup) {
            send({
                script: "location_hook",
                msg: {
                    timestamp: getTimestamp(),
                    method: method,
                    provider: provider || "N/A",
                    latitude: latitude || "N/A",
                    longitude: longitude || "N/A",
                    thread_name: threadName,
                    thread_id: threadId,
                    thread_group: threadGroup,
                    callStack: getStackTrace()
                }
            });
        }
        // Runtime.exec check
        function isRootCheck(cmd) {
            try {
                var fakeCmd;
                    if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                        fakeCmd = "grep";
                        send("[RootDetection Bypass] " + cmd + " command");
                        return fakeCmd;
                    }
                    if (cmd == "su") {
                        fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                        send("[RootDetection Bypass] " + cmd + " command");
                        return fakeCmd;
                    }
                    return false;
            }catch (err) {}
        }

        // Get all implementations
        function get_implementations(toHook) {
            try {
                var imp_args = []
                    toHook.overloads.forEach(function (impl, _) {
                        if (impl.hasOwnProperty('argumentTypes')) {
                            var args = [];
                            var argTypes = impl.argumentTypes
                            argTypes.forEach(function (arg_type, __) {
                                args.push(arg_type.className)
                            });
                            imp_args.push(args);
                        }
                    });
                    return imp_args;
            } catch (err) {}
        }

    ////////////////// END OF UTIL SCRIPTS /////////////////////////////////

});