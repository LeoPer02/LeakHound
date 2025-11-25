Java.perform(function () {

    let HurlStack;
    let HashMap;
    let MapEntry;
    let Exception;
    let Log;
    let Thread;

    try {
        Thread = Java.use('java.lang.Thread');
    } catch (err) {}

    try {
        HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
    } catch (err) {}

    try {
        HashMap = Java.use("java.util.HashMap");
    } catch (err) {}

    try {
        MapEntry = Java.use("java.util.Map$Entry");
    } catch (err) {}

    try {
        Exception = Java.use('java.lang.Exception');
    } catch (err) {}

    try {
        Log = Java.use('android.util.Log');
    } catch (err) {}



    var script_name = "volley"

    try {

        HurlStack.executeRequest.implementation = function (request, additionalHeaders) {
            //console.log("\n=== Captured Volley Request (HurlStack) ===");

            // Capture URL
            try {
                var url = request.getUrl();
            } catch (err) {

                //console.log("Error accessing URL: " + err);
            }

            // Capture Method
            try {
                var method = request.getMethod();
                var method_str = "";
                switch (method) {
                    case 3:
                        method_str = "DELETE";
                        break;
                    case -1:
                        method_str = "DEPRECATED_GET_OR_POST";
                        break;
                    case 0:
                        method_str = "GET";
                        break;
                    case 4:
                        method_str = "HEAD";
                        break;
                    case 5:
                        method_str = "OPTIONS";
                        break;
                    case 7:
                        method_str = "PATCH";
                        break;
                    case 1:
                        method_str = "POST";
                        break;
                    case 2:
                        method_str = "PUT";
                        break;
                    case 6:
                        method_str = "TRACE";
                        break;
                    default:
                        method_str = "UNKNOWN";
                        break;
                }
            } catch (err) {
                //console.log("Error accessing Method: " + err);
            }

            // Capture Headers
            try {
                var headers = request.getHeaders(); // Get headers
                var hashMap = Java.cast(headers, HashMap);
                var entrySet = hashMap.entrySet();
                var iterator = entrySet.iterator();
                var headersMap = {};

                while (iterator.hasNext()) {
                    var entry = Java.cast(iterator.next(), MapEntry);
                    var key = entry.getKey();
                    var value = entry.getValue().toString();
                    //console.log("Headers " + key + " VaLUE: " + value)
                    headersMap[key] = value;
                }

                var headersSize = headersMap.size ? headersMap.size : Object.keys(headersMap).length;
                //console.log("Headers Map size: " + headersSize);

            } catch (err) {
                //console.log("Error accessing headers: " + err);
            }

            // Capture Body
            try {
                var body = request.getBody();
            } catch (e) {
                requestDetails.body = null;
                //console.log("Error retrieving body: " + e);
            }

            var body_str = null
            try {
                body_str = byteArrayToString(body).toString()
            } catch (e) {

            }

            var callStack = stackTraceHere()
            var timestamp = Math.floor(new Date().getTime() / 1000); // Unix timestamp (seconds)

            var threadName = "NONE";
            var threadId = -1;
            var threadGroup = "NONE";
            try {
                threadName = Thread.currentThread().getName();
                threadId = Thread.currentThread().getId();
                threadGroup = Thread.currentThread().getThreadGroup().getName();
            } catch (err) {}

            var requestDetails = {
                script: script_name,
                msg: {
                    url: url,
                    method: method_str,
                    headers: headersMap,
                    body: body_str,
                    timestamp: timestamp,
                    thread_name: threadName,
                    thread_id: threadId,
                    thread_group: threadGroup,
                    callStack: callStack
                }
            }
            // Here, you can send the `requestDetails` JSON object to your server.
            //console.log("Captured Request Details:", JSON.stringify(requestDetails));

            send(requestDetails)

            return this.executeRequest(request, additionalHeaders);
        };
    } catch (err) {}

    // Helper function to convert byte array to string
    function byteArrayToString(byteArray) {
        var buffer = Java.array('byte', byteArray);
        return Java.use("java.lang.String").$new(buffer, "UTF-8");
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
