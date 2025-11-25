// This is the lowest level one can look at the network traces.
// The benefit in tracing sockets is that most, if not all, request will pass through the socket
// and therefore we won't miss any of them. However, by attaching to the socker we won't be able to look at the
// contents, which could otherwise be used to track the requests against mitm. To increase the certainty, mitm should
// also provide the source port. The chances of 2 different request being sent to the same host, with the same src port which, in theory,
// is assigned randomly, is quite low, but it could happen. Another possible metric is the use of timestamps, however, for our purposes,
// we believe using host+port should suffice.


Java.perform(function() {
        var script_name = "socket";

        let Thread;
        let sock;
        let Exception;
        let Log;
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
                    script: script_name,
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
                    script: script_name,
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


});