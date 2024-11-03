# Requirements 

Tested with Java 8.

# Compile

```
./gradlew shadowJar
```

# Usage

The logs directory needs to have the hex log files alphabetically ordered. These log files need to contain the complete sequential log entries, starting with the log entry `0x0001`. **Considering that the whole hex log files could be fabricated up to the last log entry and verify successfully, for performing a secure verification at least a new fresh log entry has to be retrieved from the HSM just before performing the verification.**

```
java -jar build/libs/yubihsm-java-verify-audit-logs-1.0-SNAPSHOT-all.jar /path/to/hex_logs_directory 
```

# TODOs

- Java for this program seems definitely overkill and I haven't verified the trustworthiness of the publicly available package `com.yubico:libyubihsm`. Evaluate to rewrite this in Python using https://github.com/Yubico/python-yubihsm or in plain Bash without any external dependency.
