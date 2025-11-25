Java.perform(function() {

    // Intercept OkHttp requests
    // This also intercepts Retrofit requests, since Retrofit is built on top of OkHttp
    // The try catch me are used to avoid running into the issue of the hook breaking due to one of the classes not being present
    let OkHttpClient;
    let Buffer;
    let Exception;
    let Log;
    let req;
    let Thread;

    try {
        Thread = Java.use('java.lang.Thread');
    } catch (err) {}
    try{
        OkHttpClient = Java.use('okhttp3.OkHttpClient');
    } catch (err) {}
    try{
        Buffer = Java.use('okio.Buffer');
    } catch (err) {}
    try{
        Exception = Java.use('java.lang.Exception');
    } catch (err) {}
    try{
        Log = Java.use('android.util.Log');
    } catch (err) {}
    try{
        req = Java.use("okhttp3.Request");
    } catch (err) {}


    var script_name = "okhttp";

    // Hook the newCall method
    try {
        OkHttpClient.newCall.implementation = function(request) {
            var result;

            try {
                result = this.newCall(request); // Call the original newCall method

                // URL, Method, and Timestamp
                var url = request.url().toString();
                var method = request.method();
                var timestamp = Math.floor(new Date().getTime() / 1000); // Unix timestamp (seconds)

                // Extract port from URL
                var port = request.url().port();
                port = (port !== -1) ? port : (url.startsWith("https") ? 443 : 80); // Default to 443 for HTTPS, 80 for HTTP

                // Extract Request Body (if present)
                var body = extractBody(request);

                // Extract Request Headers (if present)
                var headers = extractHeaders(request);

                // Get call stack
                var callStack = stackTraceHere();
                var threadName = "NONE";
                var threadId = -1;
                var threadGroup = "NONE";
                try {
                    threadName = Thread.currentThread().getName();
                    threadId = Thread.currentThread().getId();
                    threadGroup = Thread.currentThread().getThreadGroup().getName();
                } catch (err) {}
                // Create JSON object with request details
                var requestData = {
                    script: script_name,
                    msg: {
                        url: url,
                        method: method,
                        port: port,
                        headers: headers,  // Null if headers could not be retrieved
                        body: body,        // Null if body could not be retrieved
                        timestamp: timestamp,
                        thread_name: threadName,
                        thread_id: threadId,
                        thread_group: threadGroup,
                        callStack: callStack // Call stack
                    }
                };

                // Send JSON object
                send(requestData);

            } catch (error) {
                //console.log("[Error] Failed to intercept OkHttp request: " + error);
            }

            return result; // Return the result to maintain expected behavior
        };
    } catch (Err) {}

    // Extract Body of the request
    function extractBody(request) {
        try {
            var body = null;
            var requestBody = request.body();
            if (requestBody) {
                var buffer = Buffer.$new();
                requestBody.writeTo(buffer);
                body = buffer.readUtf8();
            }
            return body; // Null if body is not present or cannot be read
        } catch (error) {
            //console.log("[Error] Failed to read body: " + error);
            return null; // Return null if body extraction fails
        }
    }








    ///////////////////////////////// AUX FUNCTIONS ////////////////////////////////////////////

    // Extract Headers of the request
    // Keep in mind this will only get the headers set by the developer, not the ones added automatically by the library (content-size, etc)
    function extractHeaders(request) {
        try {
            var headers = {};
            var size = request.headers().size();
            for (var i = 0; i < size; i++) {
                var name = request.headers().name(i);
                var value = request.headers().value(i);
                headers[name] = value;
            }
            return headers; // Return the headers map
        } catch (error) {
            //console.log("[Error] Failed to extract headers: " + error);
            return null; // Return null if headers cannot be extracted
        }
    }

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
