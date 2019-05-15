# TrueChain stratum mining protocol

## Introduction

The TrueChain stratum protocol is to support pooled mining as a replacement of getwork protocol.

## Stratum methods:

### submitLogin

Login happens after TCP connection established from miner to pool.

Miner:

```
{
  "id": 1,
  "jsonrpc": "2.0",
  "method": "etrue_submitLogin",
  "params": [
    "0xb85150eb365e7df0941f0cf08235f987ba91506a", 
    "admin@example.net"
  ],
  "worker":"test"
}
```

Pool:

```
{ "id": 1, "jsonrpc": "2.0", "result": true }

Exceptions:

{ "id": 1, "jsonrpc": "2.0", "result": null, "error": { code: -1, message: "Invalid login" } }
```

params: 

wallet:0xb85150eb365e7df0941f0cf08235f987ba91506a

email(optional):admin@example.net

### getWork

Miner request from pool for new mining job

Miner:

```
{id":2,"jsonrpc": "2.0","method":"etrue_getWork"}

```

Pool:

```
{ "id":2,
  "jsonrpc": "2.0",
  "method":"etrue_getWork",
  "result": [
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	"0x5eed00000000000000000000000000005eed0000000000000000000000000000",
	"0x123456eb365e7df0941f0cf08235f98b123456eb365e7df0941f0cf08235f98b"
  ]
}

Exceptions:

{ "id": 2, "result": null, "error": { code: 0, message: "Work not ready" } }
```

params:

**headerhash**: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

**seedhash**：0x5eed00000000000000000000000000005eed0000000000000000000000000000

**target**：0x123456eb365e7df0941f0cf08235f98b123456eb365e7df0941f0cf08235f98b, the prefix 16 
bytes defines block target, suffix 16 bytes defines fruit target.

### notify

The pool informs it's miners to notify next jobs by sending:

Server:

```
{
  "id": 0,
  "jsonrpc": "2.0",
  "method": "etrue_notify",
  "params": [
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	"0x5eed00000000000000000000000000005eed0000000000000000000000000000",
	"0x123456eb365e7df0941f0cf08235f98b123456eb365e7df0941f0cf08235f98b"
  ]
}
```

**headerhash**: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef。

**seedhash**：0x5eed00000000000000000000000000005eed0000000000000000000000000000。

**target**：0x123456eb365e7df0941f0cf08235f98b123456eb365e7df0941f0cf08235f98b, the prefix 16 
bytes defines block target, suffix 16 bytes defines fruit target.


### submitwork

The miner submit result to pool once mining share found. *true* is reethminerturned if the share is accepted.

```
Request :

{
  "id": 3,
  "jsonrpc": "2.0",
  "method": "etrue_submitWork",
  "params": [
    "0x1060",
    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	"0x2b20a6c641ed155b893ee750ef90ec3be5d24736d16838b84759385b6724220d"
  ],
  "worker":"test"
}

Response:

{ "id": 3, "jsonrpc": "2.0", "result": true }
{ "id": 3, "jsonrpc": "2.0", "result": false }

Exceptions:

Pool MAY return exception on invalid share submission usually followed by temporal ban.

{ "id": 3, "jsonrpc": "2.0", "result": null, "error": { code: 23, message: "Invalid share" } }
{ "id": 3, "jsonrpc": "2.0", "result": null, "error": { code: 22, message: "Duplicate share" } }
{ "id": 3, "jsonrpc": "2.0", "result": null, "error": { code: -1, message: "High rate of invalid shares" } }
{ "id": 3, "jsonrpc": "2.0", "result": null, "error": { code: 25, message: "Not subscribed" } }
{ "id": 3, "jsonrpc": "2.0", "result": null, "error": { code: -1, message: "Malformed PoW result" } }

```

**minernonce**: 0x1060

**headerhash**: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef。

**mixhash**: 0x2b20a6c641ed155b893ee750ef90ec3be5d24736d16838b84759385b6724220d。

### dataset 

The miner use seedhash to identify dataset changes. If seedhash of new work changed, the miner should 

send request for dataset seedhash array.


Client:

```
{
  "id": 4,
  "jsonrpc": "2.0",
  "method": "etrue_seedhash",
  "params": [
    "0x5eed00000000000000000000000000005eed0000000000000000000000000000"
  ]
}
```

**seedhash**：0x5eed00000000000000000000000000005eed0000000000000000000000000000。


Server:

```
  "id": 4,
  "jsonrpc": "2.0",
  "method": "etrue_seedhash",
  "result": [
    [
      "0x323cf20198c2f3861e947d4f67e3ab63",
      "0xb7b2e24dcc9095bd9123e7b33371f6cc",
      "0x6510010198c2f3861e947d4f67e3ab63",
      "0xb7b2e24dcc9095bd9123e7b33371f6cc",
      ...
    ],
	"0x5eed00000000000000000000000000005eed0000000000000000000000000000"
  ],
  "error": null
```

**result**: 10240 seedash to generate new epoch dataset

**seedhash**: 0x5eed00000000000000000000000000005eed0000000000000000000000000000, seedhash is used
to verify dataset.

### get_version

Pool send request to get miner's version

Server:

```
{
  "id": 5,
  "method": "etrue_get_version"
}
```

Client:

```
  "id": 5,
  "result": "cpuminer/0.1.0",
  "error": null
```

### gethashrate

Pool send request to get hashrate of it's miner

Server:

```
{
  "id": 6,
  "method": "etrue_get_hashrate"
}
```

Client:

```
  "id": 6,
  "method": "etrue_get_hashrate",
  "result": "600",
  "error": null
```

**result**: 600 hash/s,hex
