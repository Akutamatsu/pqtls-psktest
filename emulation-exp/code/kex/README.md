1) for psk local timer experiment, do:
```
./psk-setsrv.sh
^Z
bg
python old_expriment.py
```
The python script above calls `s_timer.o` as clt.
Result output data will be placed into ./data directory.
After all the data has been generated, do:
```
ps -ef | grep openssl
```
and kill the PID corresponding to the process, then do:

```
teardown.sh
```

