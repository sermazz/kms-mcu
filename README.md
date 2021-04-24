# An advanced embedded Key Management System
This project has been developed as part of the course Cybersecurity for Embedded Systems
(Politecnico di Torino), held by prof. Paolo Prinetto, Gianluca Roascio and Nicoló Maunero.
Its main aim has been the design of a cryptosystem based on an advanced Key management
system for an ARM-based STM32F4-family core; the designed embedded system is able to receive
commands from an host to execute in a secure and efficient way many cryptographical operations.

The system is currently implemented to be run on an emulated version of the STM32F429ZI
core, executed by means of QEMU. The drivers (communication framework, non-volatile
memory, ...) are adapted to such platform but can easily be modified due to the layered
architecture of the software.
The project also encompasses an host-side API to interface to the device and a thorough
example of its use.

The full documentation of the project can be found in `report.pdf`, while further details
about how to install and run it are available in the rest of this readme.

## Prerequisites
Prerequisites and dependencies needed to correctly install and run the system developed
with this project are listed in the following:
- Java JRE (https://www.java.com/it/download/) or Java JDK (https://www.oracle.com/java/technologies/javase-downloads.html),
  needed to run Eclipse;
- Eclipse IDE for C/C++ (https://www.eclipse.org/), used to manage the build of the device-side
  project;
- the ARM GCC Toolchain `arm-none-eabi-gcc` (https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads),
  needed to cross-compile the device-side project for the employed MCU;
- xPack QEMU Arm (https://xpack.github.io/qemu-arm/) and xPack GNU Arm Embedded GCC binaries (https://xpack.github.io/arm-none-eabi-gcc/install/),
  needed to emulate the platform on which the device-side project is deployed (if you want to run the device-side project from Eclipse, you can also install the GNU MCU Eclipse plug-in from the Eclipse Marketplace);
- common Linux utilities, such as `make`, to use the provided `Makefile`, and a
  `gcc` distribution, to compile the host-side project.

## Installation
To set up the execution environment, open Eclipse and import the project in the `device`
directory with _Import..._, then _Existing Projects into Workspace_. Be sure to have correctly
set up all the C/C++ compilation options, the include paths, the path of the ARM GCC toolchain,
then build the project. In the root, launch

```bash
DEVICE_NUM=N make all
```

with the `DEVICE_NUM` variable set to whichever number of devices you want to have
(default value is 2). It is important to build the `device` project in Eclipse before
launching `make all`, since the compiled binary `secube-proj.elf` must exist in
`device/Debug` and be updated.

The procedure will compile the `host` binary, an extensive host software example to send
commands to the devices, and create the devices directories, to instantiate each individual
device. Use instead the target `make devices` to only instantiate the multiple devices or 
`make host` to only compile the host program.

All the devices run the same source code contained in `device`, but their private data is
managed independently from each other (i.e. their internal state, the communication channels
`channel_in` and `channel_out`, the non-volatile memory `nv_mem`).
You can manage `device` source code modifications directly from the project under `device`,
then re-build the binary in Eclipse and `make all` (or `make devices`) to reflect the changes on all
the devices instantiated for the execution, without having to re-instantiate them or reset
their non-volatile memory.

## How to run
To run the project, you have to make sure that the `qemu-system-gnuarmeclipse` binary is in
your `PATH` variable. If it is not, you can either add it with

```bash
export PATH=path/to/qemu/binary:$PATH
```

or modify the `QEMU_PATH` variable in the top-level `Makefile` to point to such binary.
After having set up the environment, you can **run the desired device** by launching

```bash
make run_device_ID
```

with `ID` set to its ID number (i.e. the number `n` in the name of its directory
`install/device_n`).
You can open a new terminal and run as many other devices as you want in parallel;
every terminal will be running a different instance of QEMU, emulating a different
device of your choice. To exit from QEMU type `q` in the terminal and then press ENTER.

To **run the host software**, launch

```bash
make run_host
```

This host software is an extensive example of all the
key management and cryptographic functionalities that the designed device is able to
offer; you will be prompted with a list of all the available commands to send to the
device, while the software will take care of communicating with the device and managing
the reply reception. You will also be asked for the parameters to customize the commands
sent to the device, along with the data on which you want it to operate.
In this process, you will be also able to select the device `ID` to which the command must be sent.

While the device is meant to be considered a black box upon which host APIs are built, you can take a look at the host `main.c` implementation to better understand how to interface to the device APIs provided by the `host_cmds` library (e.g. the data structures and the parameters that you have to provide to the device commands functions, how to manage and read the device reply).

## Cleaning
The private files of each device (i.e. the buffers of their communication channels
towards the host `channel_in` and `channel_out` and their non-volatile memory
`nv_mem`) can be cleaned by launching the following command.

```bash
make clean_mem
```

Beware that this will completely wipe the KMS database memory and all the other
data supposed to be in the device Flash memory.

The command

```bash
make clean
```

can be instead used to completely remove the devices instantiation (e.g. all the
`install/device_n` directories) and, additionally, to clean the `host` project, which can
also be managed independently from the `host` directory.
