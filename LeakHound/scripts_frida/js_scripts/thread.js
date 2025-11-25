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
// thread), although, this seems quite unusual, specially with depths longer than 2.

Java.perform(function() {

    var script_name = "thread";

    let Thread;
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
                script: script_name,
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
                script: script_name,
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
                script: script_name,
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
                script: script_name,
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
                script: script_name,
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
                script: script_name,
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
                script: script_name,
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
                script: script_name,
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

