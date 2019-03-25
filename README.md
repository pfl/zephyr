# Experimental TCP

This is an implementation of the Transmission Control Protocol (TCP) for Zephyr OS.

https://github.com/ozhuraki/zephyr/blob/tcp2-dev/subsys/net/ip/tcp2.c

https://github.com/zephyrproject-rtos/zephyr/pull/11443/

# 1 Goals

* Verifiable with the open source protocol test tools
* Clear and compact state machine
* Modular: separation of the TCP control, data and retransmission mechanisms
* Whitelisting approach: i.e. instead of blacklisting the undesired events, we pick
  only the desired, and drop the rest.
  This significantly compresses the problem space.

# 2 Sanity Check

Along with it, a TTCN-3 based sanity check suite is being developed:

https://github.com/intel/net-test-suites/blob/master/src/tcp2_check.ttcnpp

The sanity check is able to verify the control flow, retransmission and data.

**NOTE**: All modifications should pass the sanity check.

## 2.1 Sanity Check Through SLIP with qemu_x86

In this setup the following components are involved:

* samples/net/sockets/echo app (qemu_x86, overlays: overlay-tcp2.conf, overlay-tp.conf, overlay-slip.conf)
* [net-test-tools](https://github.com/intel/net-test-tools)
* [net-test-suites](https://github.com/intel/net-test-suites)

### 2.1.1 Compile and start the [net-test-tools](https://github.com/intel/net-test-tools):

```
# ./autogen.sh
# make
# ./loop-slipcat.sh
```
### 2.1.2 Compile and start samples/net/sockets/echo:

```
# git checkout tcp2-dev
# cd samples/net/sockets/echo
# mkdir build && cd build
# cmake -DBOARD=qemu_x86 -DOVERLAY_CONFIG="overlay-tcp2.conf;overlay-tp.conf;overlay-slip.conf" ..
# make run
```
### 2.1.3 Compile and run the [sanity check](https://github.com/intel/net-test-suites):

```
# . titan-install.sh
# . titan-env.sh
# cd src
# . make.sh
# ttcn3_start test_suite tcp2_check_3_runs.cfg
```
## 2.2 Sanity check with the native_posix & capturing coverage info

In this setup the following components are involved:

* samples/net/sockets/echo app (native_posix, overlays: overlay-tcp2.conf, overlay-tp.conf)
* [net-tools](https://github.com/zephyrproject-rtos/net-tools)
* [net-test-tools](https://github.com/intel/net-test-tools)
* [net-test-suites](https://github.com/intel/net-test-suites)

Already supported, to be further described here.

# 3 Test with Linux Host Tools

In this setup the following components are involved:

* samples/net/sockets/echo app (native_posix or qemu_x86)
* [net-tools](https://github.com/zephyrproject-rtos/net-tools)

## 3.1 Get Zephyrproject's [net-tools](https://github.com/zephyrproject-rtos/net-tools) and create a pseudo interface:
```
# sudo ./net-setup.sh --config zeth.conf
```
## 3.2 Compile and run samples/net/sockets/echo
### 3.2.1 native_posix
```
# cmake -DBOARD=native_posix -DOVERLAY_CONFIG="overlay-tcp2.conf" ..
```
### 3.2.2 qemu_x86 with E1000
```
# cmake -DBOARD=qemu_x86 -DOVERLAY_CONFIG="overlay-tcp2.conf;overlay-e1000.conf" ..
```
## 3.3 Connect
```
# telnet 192.0.2.1 4242
# nc 192.0.2.1 4242
```

# 4 [TODO](https://github.com/ozhuraki/zephyr/blob/tcp2-dev/TODO)

# 5 Available Overlays

Overlay | Purpose
--------|--------
[overlay-tcp2.conf](https://github.com/ozhuraki/zephyr/blob/tcp2-dev/samples/net/sockets/echo/overlay-tcp2.conf) | Overlay for the experimental TCP itself
[overlay-tp.conf](https://github.com/ozhuraki/zephyr/blob/tcp2-dev/samples/net/sockets/echo/overlay-tp.conf) | Overlay for JSON based test protocol
[overlay-slip.conf](https://github.com/ozhuraki/zephyr/blob/tcp2-dev/samples/net/sockets/echo/overlay-slip.conf) | Overlay for SLIP with qemu_x86
[overlay-e1000.conf](https://github.com/ozhuraki/zephyr/blob/tcp2-dev/samples/net/sockets/echo/overlay-e1000.conf) | Overlay for E1000 with qemu_x86





