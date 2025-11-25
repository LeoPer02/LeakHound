Java.perform(function () {

    let LocationManager;
    let FusedLocationProviderClient;
    let Location;
    let Exception;
    let Log;
    let Thread;

    try {
        Thread = Java.use('java.lang.Thread');
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
        Exception = Java.use('java.lang.Exception');
    } catch (err) {}

    try {
        Log = Java.use('android.util.Log');
    } catch (err) {}


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
});
