#!/bin/bash

# Exit on errors
set -e

# Function to detect distro and set package manager. Derivatives (mint, pop,
# devuan, raspbian, kali, rocky, alma, oracle, amazon...) use the package names
# of the distro they are built from, so match on ID first and fall back to the
# ID_LIKE list that os-release advertises for exactly this purpose.
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=${ID_LIKE:-}
    else
        echo "Unsupported distribution. Exiting."
        exit 1
    fi
    case " $DISTRO $DISTRO_LIKE " in
        *" ubuntu "*|*" debian "*)
            PKG_MANAGER="apt"
            INSTALL_CMD="apt install -y"
            UPDATE_CMD="apt update"
            # libcapnp-dev supplies the capnp-rpc pkg-config module the mining
            # IPC shim links against; libsodium-dev is required by Stratum V2.
            PACKAGES="build-essential git autoconf automake libtool pkg-config yasm libzmq3-dev curl screen libevent-dev libssl-dev bsdmainutils python3 gnupg jq libcapnp-dev libsodium-dev"
            ;;
        *" fedora "*|*" rhel "*|*" centos "*)
            PKG_MANAGER="dnf"  # or yum for older CentOS
            INSTALL_CMD="dnf install -y"
            UPDATE_CMD="dnf check-update"
            PACKAGES="gcc gcc-c++ make git autoconf automake libtool pkgconf-pkg-config yasm zeromq-devel curl screen libevent-devel openssl-devel util-linux python3 gnupg2 jq capnproto-devel libsodium-devel"
            ;;
        *)
            echo "Unsupported distribution: $DISTRO. Exiting."
            echo "Debian and Red Hat based distributions are supported; this one declares"
            echo "neither in its /etc/os-release ID or ID_LIKE."
            exit 1
            ;;
    esac
    if [ "$DISTRO" != "$DISTRO_LIKE" ] && [ -n "$DISTRO_LIKE" ]; then
        echo "Detected $DISTRO, installing $PKG_MANAGER packages for $DISTRO_LIKE."
    fi
}

# Check if sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root."
    exit 1
fi

# Bitcoin Core and CKPool are installed as systemd services, and some supported
# derivatives (devuan, antix, mx without systemd) do not have it.
if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found. This installer sets up Bitcoin Core and CKPool as"
    echo "systemd services, which this system does not use. Build and install"
    echo "manually instead, see the self install instructions in README-SOLOMINING.md."
    exit 1
fi

# Nothing on the running system is stopped or replaced until the new build has
# succeeded, so any failure before that point leaves the existing installation
# alone. POINT_OF_NO_RETURN flips once that is no longer true.
POINT_OF_NO_RETURN=false
STAGE_DIR=""
WORK_DIR=""
BITCOIN_CONF=""
CKPOOL_CONF="/etc/ckpool/ckpool.conf"

cleanup() {
    local status=$?
    [ -n "$STAGE_DIR" ] && rm -rf "$STAGE_DIR" 2>/dev/null
    [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR" 2>/dev/null
    if [ $status -ne 0 ]; then
        echo
        if $POINT_OF_NO_RETURN; then
            echo "Installation FAILED after the running services were stopped."
            echo "Your SV2 keys are untouched in /etc/ckpool and the blockchain data is intact."
            [ -f "${BITCOIN_CONF}.bak" ] && echo "Previous node config: ${BITCOIN_CONF}.bak"
            [ -f "${CKPOOL_CONF}.bak" ] && echo "Previous pool config: ${CKPOOL_CONF}.bak"
            echo "Restart the existing installation with: systemctl start bitcoind ckpool"
        else
            echo "Installation FAILED before anything on the running system was changed."
            echo "The existing installation, if any, is untouched and still running."
        fi
    fi
    return $status
}
trap cleanup EXIT

# Detect previous installation
PREVIOUS_INSTALL=false
if [ -f /etc/systemd/system/bitcoind.service ] || [ -f /etc/systemd/system/ckpool.service ] || [ -d /opt/ckpool ] || [ -d /etc/ckpool ] || [ -d /var/log/ckpool ] || [ -f /usr/local/bin/wait-for-bitcoind-sync.sh ]; then
    PREVIOUS_INSTALL=true
fi

if $PREVIOUS_INSTALL; then
    echo "Previous installation detected. Updating it will:"
    echo "  KEEP    blockchain data, SV2 keys (/etc/ckpool/sv2_*.key) and /var/log/ckpool logs"
    echo "  REPLACE bitcoin.conf and ckpool.conf (previous versions saved as .bak),"
    echo "          the systemd units, the /opt/ckpool source tree and the installed binaries"
    echo "Existing settings are offered as the defaults for each prompt below."
    echo "Nothing is stopped or replaced until the new version has been downloaded and built."
    read -p "Continue and update the existing installation? (y/N, default: no): " overwrite_answer
    if [[ ! "$overwrite_answer" =~ ^[Yy]$ ]]; then
        echo "Installation aborted."
        exit 0
    fi
fi

# Main installation
echo "Starting installation of Bitcoin Core v31.1 and CKPool-Solo. This requires sudo privileges."
echo "Warning: Bitcoin Core downloads the whole ~810GB blockchain while syncing no matter what; pruning only limits how much is kept on disk (~15GB by default here). Ensure sufficient disk space and bandwidth."
echo "Important: You cannot mine with CKPool-Solo until the Bitcoin Core blockchain is fully synchronized, which may take days depending on your hardware and network speed."

# Prompt for service user (default to current sudo user)
current_user=${SUDO_USER:-root}
echo "Optionally, choose a user to run Bitcoin Core and CKPool as (instead of $current_user)."
echo "Any existing blockchain data in the user's .bitcoin directory will be used."
read -p "Enter existing username, or 'create' to make a new 'ckpool' user (leave blank for $current_user): " input_user
if [ "$input_user" = "create" ]; then
    # Re-running the installer must not fail here just because the user was
    # created the first time round.
    if id ckpool >/dev/null 2>&1; then
        echo "User ckpool already exists, using it."
    else
        useradd -m -s /bin/bash ckpool
    fi
    service_user="ckpool"
elif [ -z "$input_user" ]; then
    service_user="$current_user"
else
    if id "$input_user" >/dev/null 2>&1; then
        service_user="$input_user"
    else
        echo "User $input_user does not exist. Exiting."
        exit 1
    fi
fi
HOME_DIR=$(getent passwd "$service_user" | cut -d: -f6)
if [ -z "$HOME_DIR" ]; then
    echo "Cannot determine the home directory for $service_user. Exiting."
    exit 1
fi
if [ ! -d "$HOME_DIR" ]; then
    mkdir -p "$HOME_DIR"
    chown "$service_user:$service_user" "$HOME_DIR"
fi

DATADIR="$HOME_DIR/.bitcoin"
BITCOIN_CONF="$DATADIR/bitcoin.conf"
IPC_SOCKET="$DATADIR/node.sock"
# Unix socket paths are limited to 107 characters by the kernel; bitcoin-node
# refuses to start rather than truncating, so catch it before doing any work.
if [ ${#IPC_SOCKET} -gt 107 ]; then
    echo "IPC socket path $IPC_SOCKET exceeds the 107 character Unix socket limit."
    echo "Choose a service user with a shorter home directory. Exiting."
    exit 1
fi

# Read back what a previous run configured so the prompts below can default to
# it. Rewriting these settings blindly is what makes a re-run dangerous: the
# prune setting cannot be flipped without consequence and new RPC credentials
# break anything else talking to the node.
existing_prune=""
existing_rpcauth=""
existing_assumevalid=""
had_bitcoin_conf=false
if [ -f "$BITCOIN_CONF" ]; then
    had_bitcoin_conf=true
    existing_prune=$(grep -E '^prune=' "$BITCOIN_CONF" | tail -1 | cut -d= -f2)
    existing_rpcauth=$(grep -E '^rpcauth=' "$BITCOIN_CONF" | tail -1)
    existing_assumevalid=$(grep -E '^assumevalid=' "$BITCOIN_CONF" | tail -1 | cut -d= -f2)
fi
existing_pass=""
existing_donation=""
existing_btcsig=""
if [ -f "$CKPOOL_CONF" ]; then
    existing_pass=$(sed -n 's/.*"pass"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' "$CKPOOL_CONF" | head -1)
    existing_donation=$(sed -n 's/.*"donation"[[:space:]]*:[[:space:]]*\([0-9.]*\).*/\1/p' "$CKPOOL_CONF" | head -1)
    existing_btcsig=$(sed -n 's/.*"btcsig"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' "$CKPOOL_CONF" | head -1)
fi

# Prompt for max disk space
MIN_PRUNE_MB=550
# A pruned node still keeps the UTXO set and block index, currently ~11 GB and
# growing, so this floor is what pruning cannot go below regardless of prune=.
PRUNED_OVERHEAD_GB=15
if $had_bitcoin_conf; then
    if [ -n "$existing_prune" ]; then
        echo "This node is currently pruned to ${existing_prune} MB of block data."
        space_default="keep the existing ${existing_prune} MB prune"
    else
        echo "This node is currently configured to keep the full chain."
        space_default="keep the existing full chain"
    fi
    echo "Changing this on a node that already has block data is not a config-only"
    echo "change, so leave the answer blank unless you mean to change it."
else
    echo "Bitcoin blockchain full size is approximately 810 GB as of August 2026."
    echo "Pruning is recommended when this node is only used for mining. CKPool needs"
    echo "the UTXO set and the current chain tip to build block templates and to verify"
    echo "and submit the blocks it solves; none of that requires keeping historical"
    echo "blocks, so pruning does not reduce what you can mine or what you are paid."
    echo "A pruned node still needs roughly ${PRUNED_OVERHEAD_GB} GB for the UTXO set and block index."
    echo "Choose the full chain only if this node will also serve historical blocks to"
    echo "other peers or rescan wallets."
    space_default="minimum ${MIN_PRUNE_MB}MB pruned"
fi
read -p "Enter maximum disk space for Bitcoin data in GB (0 for full chain, blank to ${space_default}): " max_gb
if [ -n "$max_gb" ] && ! [[ "$max_gb" =~ ^[0-9]+$ ]]; then
    echo "'$max_gb' is not a whole number of GB. Exiting."
    exit 1
fi
if [ -z "$max_gb" ]; then
    if $had_bitcoin_conf; then
        if [ -n "$existing_prune" ]; then
            prune_mb=$existing_prune
            prune_line="prune=$prune_mb"
            required_space=$((PRUNED_OVERHEAD_GB + (prune_mb + 1023) / 1024))
        else
            prune_line=""
            required_space=810
        fi
    else
        prune_mb=$MIN_PRUNE_MB
        echo "Pruning to the minimum ${MIN_PRUNE_MB} MB of block data."
        prune_line="prune=$prune_mb"
        required_space=$((PRUNED_OVERHEAD_GB + 1))
    fi
elif [ "$max_gb" -eq 0 ]; then
    prune_line=""
    required_space=810
else
    prune_mb=$((max_gb * 1024))
    if [ $prune_mb -lt $MIN_PRUNE_MB ]; then
        echo "Minimum prune size is ${MIN_PRUNE_MB} MB. Setting to ${MIN_PRUNE_MB} MB."
        prune_mb=$MIN_PRUNE_MB
    fi
    prune_line="prune=$prune_mb"
    required_space=$((PRUNED_OVERHEAD_GB + (prune_mb + 1023) / 1024))
fi

# Switching pruning on or off on a datadir that already holds blocks has
# consequences Bitcoin Core cannot undo, so make them explicit. This is keyed on
# the block data rather than on the config file: an old install whose
# bitcoin.conf has been lost or moved still has a chain that can be destroyed.
prune_unchanged=true
if [ -d "$DATADIR/blocks" ]; then
    if [ -z "$existing_prune" ] && [ -n "$prune_line" ]; then
        prune_unchanged=false
        echo
        echo "WARNING: this node currently keeps the full chain and you have asked to"
        echo "prune it to ${prune_mb} MB. Bitcoin Core will permanently delete the historical"
        echo "blocks on the next start. Recovering them means redownloading the chain."
        read -p "Enable pruning and delete the historical blocks? (y/N, default: no): " prune_answer
        if [[ ! "$prune_answer" =~ ^[Yy]$ ]]; then
            echo "Installation aborted."
            exit 0
        fi
    elif [ -n "$existing_prune" ] && [ -z "$prune_line" ]; then
        prune_unchanged=false
        echo
        echo "WARNING: this node is pruned and you have asked for the full chain."
        echo "Bitcoin Core refuses to start unpruned on a pruned datadir: it will report"
        echo "'You need to rebuild the database using -reindex to go back to unpruned mode'"
        echo "and the whole ~810 GB chain has to be redownloaded before mining resumes."
        read -p "Switch to the full chain anyway? (y/N, default: no): " prune_answer
        if [[ ! "$prune_answer" =~ ^[Yy]$ ]]; then
            echo "Installation aborted."
            exit 0
        fi
    elif [ -n "$existing_prune" ] && [ -n "$prune_line" ] && [ "$existing_prune" != "$prune_mb" ]; then
        prune_unchanged=false
    fi
fi

# Disk space check (add 10% buffer to required_space). An existing datadir that
# keeps its storage settings has already paid for the space it uses.
if [ -d "$DATADIR/blocks" ] && $prune_unchanged; then
    echo "Keeping the existing storage configuration, skipping the disk space check."
else
    required_space=$((required_space * 110 / 100))
    available_space=$(df -k --output=avail "$HOME_DIR" | tail -n 1)
    available_space_gb=$((available_space / 1024 / 1024))
    if [ "$available_space_gb" -lt "$required_space" ]; then
        echo "Warning: Insufficient disk space. Required: ~${required_space} GB, Available: ${available_space_gb} GB in $HOME_DIR."
        read -p "Continue anyway? (y/N, default: no): " continue_answer
        if [[ ! "$continue_answer" =~ ^[Yy]$ ]]; then
            echo "Installation aborted due to insufficient disk space."
            exit 1
        fi
        echo "Proceeding with installation despite low disk space. This may cause issues."
    fi
fi

# Prompt for assumevalid block hash
DEFAULT_ASSUMEVALID="0000000000000000000081c26d870f8ac4a0217b8c6dab7b63c25f03b3882c52"
if [ -n "$existing_assumevalid" ]; then
    assumevalid_default="keep existing $existing_assumevalid"
else
    assumevalid_default="$DEFAULT_ASSUMEVALID at block 960804"
fi
read -p "To speed up blockchain sync, enter a trusted recent block hash for assumevalid (default: $assumevalid_default, or 0 to disable): " assumevalid_hash
if [ "$assumevalid_hash" = "0" ]; then
    assumevalid_line=""
    echo "Assumevalid disabled. Full blockchain verification will be performed."
elif [ -n "$assumevalid_hash" ]; then
    echo "Warning: Using assumevalid skips signature verification up to this block, reducing security. Ensure the hash is from a trusted source."
    assumevalid_line="assumevalid=$assumevalid_hash"
elif [ -n "$existing_assumevalid" ]; then
    assumevalid_line="assumevalid=$existing_assumevalid"
else
    assumevalid_line="assumevalid=$DEFAULT_ASSUMEVALID"
fi

# Prompt for donation to CKPool author
if [ -n "$existing_donation" ]; then
    read -p "Support CKPool author with a donation on mined blocks? (Y/n, default: keep existing ${existing_donation}%): " donation_answer
    if [[ "$donation_answer" =~ ^[Nn]$ ]]; then
        donation_line=""
        echo "Donation disabled."
    else
        donation_line="\"donation\" : $existing_donation,"
        echo "Keeping the existing ${existing_donation}% donation. Thank you for supporting CKPool development!"
    fi
else
    read -p "Support CKPool author with a 0.5% donation on mined blocks? (y/N, default: no): " donation_answer
    if [[ "$donation_answer" =~ ^[Yy]$ ]]; then
        donation_line='"donation" : 0.5,'
        echo "Donation of 0.5% enabled. Thank you for supporting CKPool development!"
    else
        donation_line=""
        echo "Donation disabled. You can enable it later in $CKPOOL_CONF."
    fi
fi

# Prompt for coinbase signature
if [ -n "$existing_btcsig" ]; then
    read -p "Enter a signature string to include in the coinbase of mined blocks (blank to keep '$existing_btcsig', - for none): " btcsig
    if [ -z "$btcsig" ]; then
        btcsig="$existing_btcsig"
    elif [ "$btcsig" = "-" ]; then
        btcsig=""
    fi
else
    read -p "Enter an optional signature string to include in the coinbase of mined blocks (leave blank for none): " btcsig
fi
# Quotes and backslashes would produce an unparseable ckpool.conf.
btcsig=$(printf '%s' "$btcsig" | tr -d '"\\')
if [ -n "$btcsig" ]; then
    btcsig_line="\"btcsig\" : \"$btcsig\","
    echo "Coinbase signature '$btcsig' will be included in mined blocks."
else
    btcsig_line=""
    echo "No coinbase signature set. You can add one later in $CKPOOL_CONF."
fi

detect_distro
# dnf check-update exits 100 when updates are available, which would trip set -e.
$UPDATE_CMD || true

# Install dependencies (for Bitcoin Core, CKPool build including the mining IPC
# and Stratum V2 support, rpcauth.py, tarball verification, and jq for sync check)
$INSTALL_CMD $PACKAGES

# Enable persistent journald storage
echo "Enabling persistent journal storage for easier log access..."
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true

# Download and verify Bitcoin Core v31.1 tarball into a scratch directory that
# the exit trap removes, rather than littering the invoking directory.
WORK_DIR=$(mktemp -d)
cd "$WORK_DIR"
BITCOIN_VERSION="31.1"
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    BITCOIN_TAR="bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz"
elif [ "$ARCH" = "aarch64" ]; then
    BITCOIN_TAR="bitcoin-${BITCOIN_VERSION}-aarch64-linux-gnu.tar.gz"
else
    echo "Unsupported architecture: $ARCH. Exiting."
    exit 1
fi
BASE_URL="https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}"
curl -fLO ${BASE_URL}/${BITCOIN_TAR}
curl -fLO ${BASE_URL}/SHA256SUMS
curl -fLO ${BASE_URL}/SHA256SUMS.asc

# Import Bitcoin Core builder GPG keys
git clone https://github.com/bitcoin-core/guix.sigs -b main --depth 1 "$WORK_DIR/guix.sigs"
gpg --import "$WORK_DIR"/guix.sigs/builder-keys/* || true
rm -rf "$WORK_DIR/guix.sigs"

# Verify hash and signature
sha256sum --ignore-missing --check SHA256SUMS || { echo "Hash verification failed. Exiting."; exit 1; }
gpg --verify SHA256SUMS.asc || { echo "Signature verification failed. Exiting."; exit 1; }

# Extract tarball
tar -zxf ${BITCOIN_TAR}

# RPC credentials. Reuse the existing pair on an update: regenerating them
# silently breaks every other client configured against this node, and the
# plaintext password is only recoverable from the pool config we are replacing.
reuse_rpc=false
if [ -n "$existing_rpcauth" ] && [ -n "$existing_pass" ] && [[ "$existing_rpcauth" == rpcauth=ckpooluser:* ]]; then
    reuse_rpc=true
fi
if $reuse_rpc; then
    echo "Reusing the existing RPC credentials for user ckpooluser."
    rpcauth_line="$existing_rpcauth"
    rpc_password="$existing_pass"
else
    rpc_output=$(cd bitcoin-${BITCOIN_VERSION} && python3 ./share/rpcauth/rpcauth.py ckpooluser)
    rpcauth_line=$(echo "$rpc_output" | grep '^rpcauth=')
    rpc_password=$(echo "$rpc_output" | tail -1 | sed 's/Your password://' | tr -d '[:space:]')
    if $had_bitcoin_conf; then
        echo "Could not reuse the previous RPC credentials; new ones have been generated."
        echo "Any other client configured against this node will need updating."
    fi
fi

# Calculate dbcache: 25% of total memory in MB, capped at 12000 MB
total_mem=$(free -m | awk '/Mem:/ {print $2}')
dbcache=$((total_mem * 25 / 100))
if [ $dbcache -gt 12000 ]; then
    dbcache=12000
fi

# Build CKPool-Solo in a staging directory. Everything that can fail - the
# download, the verification and the compile - happens while the existing
# installation is still running and untouched.
STAGE_DIR=$(mktemp -d /opt/.ckpool-build-XXXXXX)
git clone https://bitbucket.org/ckolivas/ckpool.git "$STAGE_DIR/ckpool"
# autogen.sh fetches the bundled secp256k1 submodule, which SV2 needs for its
# ellswift/schnorrsig support. --enable-sv2 makes configure fail loudly if the
# SV2 dependencies are missing rather than silently building without it; the
# mining IPC is enabled automatically when capnp-rpc is present.
(
    cd "$STAGE_DIR/ckpool"
    ./autogen.sh
    ./configure --enable-sv2
    make -j$(nproc)
)

# ---------------------------------------------------------------------------
# Everything below here modifies the running installation.
# ---------------------------------------------------------------------------
POINT_OF_NO_RETURN=true

systemctl stop ckpool 2>/dev/null || true
systemctl stop bitcoind 2>/dev/null || true

# Install the new binaries with the services stopped so a running bitcoin-node
# is never replaced underneath itself.
cp -r bitcoin-${BITCOIN_VERSION}/bin/* /usr/local/bin/
# The multiprocess node lives in libexec from v31 on, and the bin/bitcoin
# wrapper resolves it relative to its own location as ../libexec/bitcoin-node.
mkdir -p /usr/local/libexec
cp bitcoin-${BITCOIN_VERSION}/libexec/bitcoin-node /usr/local/libexec/

make -C "$STAGE_DIR/ckpool" install
rm -rf /opt/ckpool
mv "$STAGE_DIR/ckpool" /opt/ckpool
chown -R $service_user:$service_user /opt/ckpool

# Set up Bitcoin Core config and datadir
mkdir -p "$DATADIR"
# Only walk the datadir when the owner is actually wrong; a recursive chown of a
# synced chain is a long and pointless operation on every update.
datadir_owner=$(stat -c %U "$DATADIR" 2>/dev/null || echo "")
if [ "$datadir_owner" != "$service_user" ]; then
    echo "Setting ownership of $DATADIR to $service_user, this may take a while on a large datadir..."
    chown -R $service_user:$service_user "$DATADIR"
fi
if [ -f "$BITCOIN_CONF" ]; then
    cp -a "$BITCOIN_CONF" "${BITCOIN_CONF}.bak"
    echo "Previous node config saved as ${BITCOIN_CONF}.bak"
fi
cat << EOF > "$BITCOIN_CONF"
$rpcauth_line
server=1
$prune_line
$assumevalid_line
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
ipcbind=unix:$IPC_SOCKET
zmqpubhashblock=tcp://127.0.0.1:28332
blockmaxweight=3900000
checkblocks=6
blockreconstructionextratxn=1000
dbcache=$dbcache
minrelaytxfee=0.000001
blockmintxfee=0.00001
EOF
chown $service_user:$service_user "$BITCOIN_CONF"
chmod 640 "$BITCOIN_CONF"

# Set up CKPool config (minimal, per README-SOLOMINING.md)
mkdir -p /etc/ckpool
# /etc/ckpool is never removed: it holds the SV2 Noise keys, which are the
# pool's permanent identity. Miners pin the authority public key in their
# connection URL, so regenerating them would force every SV2 miner to be
# reconfigured.
if ls /etc/ckpool/sv2_*.key >/dev/null 2>&1; then
    echo "Existing SV2 keys kept, the pool's authority public key is unchanged."
fi
if [ -f "$CKPOOL_CONF" ]; then
    cp -a "$CKPOOL_CONF" "${CKPOOL_CONF}.bak"
    echo "Previous pool config saved as ${CKPOOL_CONF}.bak"
fi
# btcd is still required alongside the IPC socket: ckpool uses JSON-RPC to
# validate addresses and as the getblocktemplate fallback whenever the IPC
# template service is not ready. A usable ipcmining socket is on its own enough
# to drive templates and tip notifications. serverurl must be listed explicitly,
# because configuring sv2url would otherwise suppress the default SV1 listener.
cat << EOF > "$CKPOOL_CONF"
{
  $donation_line
  $btcsig_line
  "btcd" : [
    {
      "url" : "127.0.0.1:8332",
      "auth" : "ckpooluser",
      "pass" : "$rpc_password",
      "notify" : true
    }
  ],
  "ipcmining" : "$IPC_SOCKET",
  "serverurl" : [
    "0.0.0.0:3333"
  ],
  "sv2url" : [
    "0.0.0.0:3336"
  ],
  "sv2_authority_key" : "/etc/ckpool/sv2_authority.key",
  "sv2_static_key" : "/etc/ckpool/sv2_static.key",
  "startdiff" : 10000,
  "logdir" : "/var/log/ckpool"
}
EOF
# The pool config holds the plaintext RPC password.
chmod 640 "$CKPOOL_CONF"
mkdir -p /var/log/ckpool
chown -R $service_user:$service_user /etc/ckpool /var/log/ckpool

# Create wait script for bitcoind sync with block progress
cat << EOF > /usr/local/bin/wait-for-bitcoind-sync.sh
#!/bin/bash

echo "Starting wait for bitcoind sync at \$(date)"
echo "Using config file: $BITCOIN_CONF"
while true; do
    if ! bitcoin-cli -conf="$BITCOIN_CONF" -rpcuser=ckpooluser -rpcpassword=$rpc_password getblockchaininfo >/dev/null 2>&1; then
        echo "Waiting for bitcoind to start... at \$(date)"
        sleep 60
        continue
    fi
    info=\$(bitcoin-cli -conf="$BITCOIN_CONF" -rpcuser=ckpooluser -rpcpassword=$rpc_password getblockchaininfo 2>/dev/null)
    if [ \$? -ne 0 ]; then
        echo "Error querying bitcoind: RPC failure at \$(date)"
        sleep 60
        continue
    fi
    synced=\$(echo "\$info" | jq '.initialblockdownload' 2>/dev/null)
    blocks=\$(echo "\$info" | jq '.blocks' 2>/dev/null)
    headers=\$(echo "\$info" | jq '.headers' 2>/dev/null)
    if [ -z "\$synced" ] || [ -z "\$blocks" ] || [ -z "\$headers" ]; then
        echo "Error parsing bitcoind info at \$(date)"
        sleep 60
        continue
    fi
    if [ "\$synced" = "false" ]; then
        echo "Blockchain synced: \$blocks blocks at \$(date)"
        break
    fi
    if [ "\$blocks" -gt 0 ] && [ "\$headers" -gt 0 ]; then
        progress=\$(echo "scale=2; \$blocks * 100 / \$headers" | bc)
        echo "Syncing: \$blocks/\$headers blocks (\${progress}%) at \$(date)"
    else
        echo "Waiting for bitcoind to start syncing... at \$(date)"
    fi
    sleep 60
done
EOF
# This script embeds the plaintext RPC password, so keep it off world read.
chown $service_user:$service_user /usr/local/bin/wait-for-bitcoind-sync.sh
chmod 750 /usr/local/bin/wait-for-bitcoind-sync.sh

# Create helper to print the miner-facing addresses. The SV2 authority public
# key is only created when ckpool first starts, so this reads it back from the
# log rather than being baked in at install time.
cat << EOF > /usr/local/bin/ckpool-mining-urls.sh
#!/bin/bash

CKLOG=/var/log/ckpool/ckpool.log
ip=\$(hostname -I 2>/dev/null | awk '{print \$1}')
[ -n "\$ip" ] || ip="[machine IP]"

echo "Stratum V1 mining address: stratum+tcp://\$ip:3333"
echo "  Username: your Bitcoin address   Password: x"
echo
b58=\$(grep -h "SV2 authority URL path" "\$CKLOG" 2>/dev/null | tail -1 | sed 's|.*<host>:<port>/\\([^)]*\\)).*|\\1|')
if [ -n "\$b58" ]; then
    echo "Stratum V2 mining address: stratum2+tcp://\$ip:3336/\$b58"
    echo "  Authority public key: \$b58"
    echo "  Username: your Bitcoin address   Password: x"
else
    echo "Stratum V2 mining address: stratum2+tcp://\$ip:3336/<authority public key>"
    echo "  The authority public key is generated the first time ckpool starts,"
    echo "  which only happens once the blockchain has finished syncing."
    echo "  Re-run ckpool-mining-urls.sh then, or search \$CKLOG for 'SV2 authority'."
fi
EOF
chmod +x /usr/local/bin/ckpool-mining-urls.sh

# Create systemd services
cat << EOF > /etc/systemd/system/bitcoind.service
[Unit]
Description=Bitcoin Core node (multiprocess, mining IPC)
After=network.target

[Service]
User=$service_user
# bitcoin-node rather than bitcoind: only the multiprocess binary implements
# -ipcbind and the Cap'n Proto mining interface ckpool builds templates from.
ExecStart=/usr/local/libexec/bitcoin-node -conf="$BITCOIN_CONF" -datadir="$DATADIR" -printtoconsole
Restart=always
TimeoutSec=120
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/ckpool.service
[Unit]
Description=CKPool Solo
After=bitcoind.service

[Service]
User=$service_user
ExecStart=/bin/bash -c '/usr/local/bin/wait-for-bitcoind-sync.sh && exec /usr/local/bin/ckpool -B -q -c /etc/ckpool/ckpool.conf'
StandardOutput=journal
StandardError=journal
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bitcoind ckpool
systemctl start bitcoind ckpool

echo "Installation complete! CKPool-Solo is set to start on ports 3333 (Stratum V1) and 3336 (Stratum V2) after blockchain sync."
echo "Bitcoin Core runs as bitcoin-node with its mining IPC socket at $IPC_SOCKET, which CKPool uses for block templates and notifications."
echo "Important: You cannot mine until the Bitcoin Core blockchain is fully synchronized, which may take days."
echo "Check sync progress with:"
echo "  - journalctl -u ckpool -f (block progress until CKPool starts)"
echo "  - journalctl -u bitcoind -f (detailed sync logs)"
echo "  - tail -f $DATADIR/debug.log (detailed sync logs)"
echo "CKPool startup is delayed until sync completes (monitor with: journalctl -u ckpool -f)."
echo
echo "Mining addresses (replace [machine IP] with this machine's address if shown):"
/usr/local/bin/ckpool-mining-urls.sh
echo
echo "Re-run ckpool-mining-urls.sh at any time to print these again."
echo "SV2 miners must supply the authority public key, which is the base58 string at the end of the stratum2 URL. It is stored permanently in /etc/ckpool/sv2_authority.key and is preserved if you re-run this installer, so it does not change."
if $PREVIOUS_INSTALL; then
    echo "The previous configs were kept as ${BITCOIN_CONF}.bak and ${CKPOOL_CONF}.bak; copy across any settings you had added by hand and restart the services."
fi
echo "Monitor logs:"
echo "  - CKPool: tail -f /var/log/ckpool/ckpool.log (full logs) or journalctl -u ckpool -f (block progress, then reduced CKPool logs)"
echo "  - Bitcoin Core: tail -f $DATADIR/debug.log or journalctl -u bitcoind -f"
echo "Edit configs in $BITCOIN_CONF and $CKPOOL_CONF if needed, then restart services with: systemctl restart bitcoind ckpool"
