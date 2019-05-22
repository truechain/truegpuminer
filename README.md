# trueminer

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg)](https://github.com/RichardLitt/standard-readme)

> Truechain miner with OpenCL and stratum support

**trueminer** is an truechain GPU mining worker. It originates from [ethminer] project.

## Features

* OpenCL mining
* stratum mining without proxy
* OpenCL devices picking
* farm failover (getwork + stratum)


## Table of Contents

* [Install](#install)
* [Usage](#usage)
* [Build](#build)
* [Contribute](#contribute)


## Install

Standalone **executables** for *Linux* and *Windows* are provided in the [Releases]
section.

Download an archive for your operating system and unpack the content to a place
accessible from command line. The trueminer is ready to go.


## Usage

The **trueminer** is a command line program. You can launch it from a Linux
console. For a full list of available command, please run:

```sh
trueminer --help
```

### Connecting to pools

Pool connection definition is issued via `-P` argument which has this syntax:

```
-P scheme://user[.workername][:password]@hostname:port[/...]
```

where `scheme` can be either of:

* `http` for getwork mode (getrue)
* `stratum+tcp` for plain stratum mode

Stratum protocol detail can be found in the [specification](https://github.com/truechain/trueminer/blob/master/protocol.md).

For getwork mode(solo mining):

```
trueminer -G -P http://hostname:port
```
You need to specify *hostname* and *port* according to you getrue rpc address.

For stratum pool:

```
trueminer -G -P stratum+tcp://WALLET.WORKER@hostname:port
```


### Building from source

#### Requirements

On **Ubuntu**, install driver for nvidia GPU

```
add-apt-repository ppa:graphics-drivers/ppa
apt-get install nvidia-418 nvidia-418-dev nvidia-opencl-dev nvidia-opencl-icd-418
```

On **Windows**, install [Visual Studio 2017](https://www.visualstudio.com/downloads/)

#### Instructions

1. Make sure git submodules are up to date:

    ```shell
    git submodule update --init --recursive
    ```

2. Create a build directory:

    ```shell
    mkdir build
    cd build
    ```

3. Configure the project with CMake.

    ```shell
    cmake ..
    ```

    **Note:** On *Windows*, sepecify target platform name(x64):

    ```shell
    cmake .. -G "Visual Studio 15 2017 Win64"
    ```

4. Build the project.

    ```shell
    cmake --build .
    ```

    **Note:** On *Windows*, specify the build config for cmake:

    ```shell
    cmake --build . --config Release
    ```

5. _(Optional)_ Install the built executable:

    ```shell
    make install
    ```

## Contribute

All bug reports, pull requests and code reviews are very much welcome.


## License

Licensed under the [GNU General Public License, Version 3](LICENSE).


[ethminer]: https://github.com/ethereum-mining/ethminer
[Releases]: https://github.com/truechain/trueminer/releases
