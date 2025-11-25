Java.perform(function () {
    let ContentResolver;
    let Cursor;
    let Thread;

    try {
        Thread = Java.use('java.lang.Thread');
    } catch (err) {}

    try {
        ContentResolver = Java.use("android.content.ContentResolver");
        Cursor = Java.use("android.database.Cursor");
    } catch (err) {}

    let Exception;
    let Log;

    try {
        // Try to assign the classes to variables
        Exception = Java.use('java.lang.Exception');
    } catch (err) {}
    try {
        Log = Java.use('android.util.Log');
    } catch (err) {}


    var script_name = "content_query";

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
                script: script_name,
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

    //console.log("[+] Hooking complete!");
});
