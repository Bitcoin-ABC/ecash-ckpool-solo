# Local solo mining

## All-in-one solo mining quickstart

```bash
wget https://api.bitbucket.org/2.0/repositories/ckolivas/ckpool/src/master/scripts/install-ckpool-solo.sh
chmod +x install-ckpool-solo.sh
sudo ./install-ckpool-solo.sh
```

This will download ckpool source code, v31.1 bitcoin daemon binary, check its
validity, install the daemon, build ckpool, and install it, configured for
solo mining. Follow the prompts or simply press enter for the default settings.

The node installed is bitcoin-node, the multiprocess build of Bitcoin Core,
rather than bitcoind. Only bitcoin-node exposes the Cap'n Proto mining IPC
interface, which ckpool uses in preference to getblocktemplate for building
block templates and for learning about new blocks. JSON-RPC is still
configured and used for address validation and as the fallback whenever the
IPC interface is unavailable, so nothing breaks if the socket goes away.

Should work on any .deb or .rpm based linux distribution (ubuntu, debian,
fedora, centos, rhel, and derivatives such as mint, pop, raspbian, kali,
devuan, rocky, alma, oracle and amazon linux, identified by the ID_LIKE field
in /etc/os-release) to download required packages. Installs both as systemd
services as the current user but can configure a new ckpool user for both. It
defaults to running a minimally pruned bitcoin blockchain, keeping only 550MB
of block data, to minimise hard drive storage. Pruning costs you nothing on a
node used only for mining: ckpool needs the UTXO set and the current chain tip
to build block templates and to verify and submit the blocks it solves, and
none of that requires historical blocks, so neither what you can mine nor what
you are paid is affected. A pruned node still needs roughly 15GB for the UTXO
set and block index, and the whole chain is still downloaded during initial
sync, so pruning saves disk space but not bandwidth. Enter 0 at the disk space
prompt to keep the full chain instead, which is only worth doing if the node
will also serve historical blocks to other peers or rescan wallets. That
currently needs over 800GB, so ideally you should at least have double this
space on the drive. You will be given the option to use a checkpoint hash to
speed up the initial blockchain download, or disable it for maximum paranoia.
It will use any existing blockchain data in `~/.bitcoin` if it exists for the
chosen user.

The node will be preconfigured with suitable mining defaults, and ckpool will
be built with both Stratum V2 and mining IPC support and started in solo
mining mode on the current machine. You will be unable to mine to it until the
bitcoin daemon has synced up the full blockchain.

Two mining ports are configured. Stratum V1 listens on 3333 as before, and
Stratum V2 listens on 3336 alongside it, so existing V1 miners keep working
unchanged. V2 miners connect to a URL of the form

```
stratum2+tcp://[machine IP]:3336/[authority public key]
```

where the authority public key is a base58 string identifying this pool. It is
generated the first time ckpool starts and stored permanently in
`/etc/ckpool/sv2_authority.key`, along with the server static key in
`/etc/ckpool/sv2_static.key`. Both are kept if you re-run the installer, so the
key your miners are configured with never changes. Run

```bash
ckpool-mining-urls.sh
```

at any time to print the V1 and V2 mining addresses, including the authority
public key. Before the blockchain has finished syncing ckpool has not started
yet and the key does not exist, so run it again once mining begins.

You will be given the option to enable donation to the ckpool author, and a
custom signature to be added to any solved blocks.

The installer can be re-run at any time to update an existing installation. It
keeps the blockchain data, the SV2 keys and the ckpool logs, reuses the existing
RPC credentials, and offers every previous setting as the default answer, so
pressing enter through the prompts updates the software without changing the
configuration. The previous `bitcoin.conf` and `ckpool.conf` are saved as
`.bak` alongside the new ones. Nothing running is stopped or replaced until the
new version has been downloaded, verified and built, and changing the pruning of
a node that already holds block data requires an explicit confirmation, since
Bitcoin Core cannot undo that in either direction.

## Self install instructions

(build instructions not included.)

Get a password from bitcoin core for the RPC (remote procedure calls) to allow
the pool to talk to it. You will need bitcoin core source code.

Within the bitcoin source code directory type the following command:

```bash
share/rpcauth/rpcauth.py ckpool
```

This will give you a message such as:

```
String to be appended to bitcoin.conf:
rpcauth=ckpool:c6f55b4a74b8fcbca4e8b2be22d7d53b$e2ca5e642d7ef4f43ab2524964dc6b3625ccfde09a97866c5b97c40622192149
Your password:
sI7jIjC61U9ZYTT29GnBpm0Rg1qQV9w_TXOfBF1vOM8
```

Edit `bitcoin.conf`, enabling RPC (remote procedure calls) and add the rpcauth
line above. The following would allow ckpool to talk to a bitcoin daemon running
on the same hardware:

```ini
server=1
rpcauth=ckpool:c6f55b4a74b8fcbca4e8b2be22d7d53b$e2ca5e642d7ef4f43ab2524964dc6b3625ccfde09a97866c5b97c40622192149
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
zmqpubhashblock=tcp://127.0.0.1:28332
```

Make sure to use the rpcauth line you got when running the rpcauth command.

Create or modify a ckpool configuration file (such as `ckpool.conf`), including
the minimum necessary entries. Make sure to use the password you got in step 1.

```json
{
"btcd" :  [
        {
        "url" : "127.0.0.1:8332",
        "auth" : "ckpool",
        "pass" : "sI7jIjC61U9ZYTT29GnBpm0Rg1qQV9w_TXOfBF1vOM8",
        "notify" : true
        }
]
}
```

Start ckpool from the source code directory (pointing to the configuration file
only if it has a different name to `ckpool.conf` or is placed elsewhere) in solo
mode:

```bash
src/ckpool -B
```

Point the pools entry on your mining hardware to the local IP address where
ckpool is running on port 3333, setting a username to the bitcoin address you
wish to mine to, and put anything in the password field (such as `x`), e.g. if
ckpool has a local IP address of 192.168.1.100:

```
url: 192.168.1.100:3333
username: 1PKN98VN2z5gwSGZvGKS2bj8aADZBkyhkZ
password: x
```

Any valid bitcoin address will work

(Hope for) profit.

## Optional changes

Most of the ckpool configuration options would not need to be modified for a
local solo mining operation, and some of the config options are not used in
solo mode. The `ckpool.conf` included with the source has all the available
configuration options and is not recommended to be used as is. The following
options may be useful for a local solo mining operation.

Mining to one fixed address. If you only plan to mine to one fixed address and
not have to worry about setting the username in every piece of mining hardware,
you can set a bitcoin address to mine to as follows:

```json
"btcaddress" : "14BMjogz69qe8hk9thyzbmR5pg34mVKB1e",
```

You must then start ckpool withOUT the `-B` option. This would mine to the
address 14BMjogz69qe8hk9thyzbmR5pg34mVKB1e, so modify it to the bitcoin address
you wish to mine to.

You can set the starting diff (instead of the default 42) on the pool as
follows:

```json
"startdiff" : 10000,
```

You can define a signature to be mined into any blocks you solved as follows:

```json
"btcsig" : "/mined by ck/",
```

You may wish to enable a donation to the author of ckpool with any blocks found
as a percentage (such as 0.5%) as follows:

```json
"donation" : 0.5,
```

Donation is completely optional and disabled by default, but most appreciated.
0.5% would be a reasonable value.

By default ckpool binds to every local IP address on the hardware it's run on,
but you can restrict it to certain addresses or change the port it runs on as
follows:

```json
"serverurl" : [
	"127.0.0.1:3333",
	"192.168.1.100:3334"
],
```

In addition, if you specify a port above 4000, it will become a "high diff"
port that sets the minimum difficulty to 1 million.

You can specify a different configuration file as follows:

```bash
src/ckpool -B -c myconfig.conf
```

or you can start ckpool with a different name and it will look for the
associated configuration

```bash
src/ckpool -B -n local
```

this will look for a configuration file called `local.conf`

## Notes

Json is very strict with its field processing although spacing is flexible. The
most common error to watch out for is to NOT put a comma after the last field.

You can mine with a pruned blockchain if you are short on space, though it is
not recommended as it can add more latency.

Bitcoin core is NOT optimised for mining by default without modification, and
mining solo locally should be reserved as a backup operation only unless you
have the skills, hardware, and data centre quality connectivity to minimise
latency.

Mining on testnet may create a cascade of solved competing blocks when the diff
is 1. This is normal as the default behaviour is optimised around mainnet
mining where block solving is rare.

Good luck.
