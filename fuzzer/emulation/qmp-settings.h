#define QMPHOST "localhost"
#define QMPPORT 4444
#define BUFSIZE 1024
#define QMP_CMD_CAPABILITES "{\"execute\":\"qmp_capabilities\"}" 
#define QMP_CMD_MEMSAVE_FMT "{ \"execute\": \"memsave\", \"arguments\": {\"val\": %ld, \"size\": %lu, \"filename\": \"%s\"} }"
