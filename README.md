# save-dweb-backend
DWeb Backend for the Save app based on Veilid and Iroh

## Running

- Run tests with `cargo test`
- After changing, format with `cargo fmt` and lint with `cargo clippy`
- You can run the backend as a process with `cargo run`

## Architecture

![graphviz architecture](https://github.com/tripledoublev/save-dweb-backend/assets/631268/ebea73cb-a709-4d86-8bd3-63290cdb9d88)

Source for the above diagram is [here](graphviz_architecture.dot).

## Plans

We'll make use of Veilid for peer discovery and connections, and for public key cryptography. Iroh will be used for blob replication. We'll make an adapter to iroh's store class based on veilid's protected store.

Flow looks like this:
- if user has no groups, they create a new one
- user loads group info via the dht
- user loads the other users DataRepos and tunnels from the dht
- the user then creates a new DataRepo for the group and advertises their tunnel
- when trying to download a file it'll send a message to the others to ask who "has" the blob
- it will then use the iroh collections/blobs sync protocol to download in paralell

### Backend Core Class

- init storage adapters
- init veilid
- track ongoing blob requests / group participation
    - map of requests/responses with group and blob info?
- method to `loadGroup(keypair) => Group`
- veilid table is used to cache group data and personal repo info

### Group

- identifed by a veilid dht record keypair
- keypair secret is used to generate encryption secret for values in dht
- first subkey is the group name
- other subkeys are encrypted with the secret in the format of `encrypted(repoPublicKey)`
- `constructor(routingContext, keyPair)`
- `listRepos() => DataRepo`
- `lstTunnels() => []PublicKey`
- `getBlob(groupPublicKey, repoPublicKey, fileName) => Result<async iterator bytes[]>`
- `joinGroup(keyPair) => Result`
- `listMembers(groupPublicKey) => {name, repooPublicKey}[]`
- `encrypt([]bytes data) => Result<bytes[]>`
- `decrypt([]bytes encryptedData) => Result<bytes[]>`
- `dhtGet(subkey number) => Result<bytes[]>` (decrypts after get)
- `dhtPut(subkey number, bytes[]) => Result` (encrypts before put)
- `dhtNumKeys() => Result<number>`
- `dhtHasRepo(publicKey) => Result<bool>`

### DataRepo

- identified with veilid dht record keypair
- encrypted with same secret as group
- first subkey is a json blob with `{"name": "example"}`
- second is the hash of an iroh collection
- other subkeys are veilid tunnel public keys
    - before "closing" we should make sure to remove our tunnel from the list
- collection points to blob hashes
- read/list APIs for readers
- writing does the following
    - upload blob and get hash
    - update collection key to set to hash
    - update dht record with new collection root hash
- delete should just clear the key from the collection and trigger an update
    - TODO: How do we deal with clearing delete? Seperate data stores per repo?
- constructor should take `(groupSecret, publicKey, secretKey?)`
- `getName() => Name?`
- `getTunnels() => []PublicKey`
- `write(name String, async iterator []bytes) => Result`
- `read(name) => Result<async iteraor []bytes>`
- `syncAll(onProgress) => Result`

## Radmap:

- get veilid building and running inside backend class
    - Pass storage location in the constructor
    - Add veilid instance as property of backend struct (in a box?)
    - Tie veilid to the lifetime of the backend
    - Stop veilid node in stop method
    - For the test find a way to make the storage ephemeral, e.g. make a path in `/tmp`, maybe use a utility
- create groups and publish to veilid with name, read name from keypair
    - store a map of groups from their public key to a `Box<Group>` in the backend
    - Create a routing context per group
    - Inside create group create a new dht record, also use veilid crypto to generate a random encryption key
    - Store dht record in Group
    - Invoke `set_name` on group which will set subkey `0` to the string
    - Have `get_name` read from subkey 0
    - write a unit test to see that you can write then read the name
    - Store group keypair/secret key in protected table store with the public key as the "key" and the data as the value. (in cbor using serde?)
    - When loading the group by public key attempt to read from the store, error if not available
    - Add method to load group from public key, encryption key, `Option<private key>` which will skip creating a new dht record, have the public key only api invoke this
    - add method to close the group and unload the dht record / remove from the backend map
    - write a test to see that we can load a group from storage after we closed it, and after we stopped the veilid node / started a new one
    - Add `encrypt` and `decrypt` methods to the Group
    - Encrypt the data before setting in `set_name`, decrypt in `get_name`, do so via the dht wrappers
    - Ensure the `get_name` tests still work.
- create data repo with name and advertise to dht/read name back
- add own repo to group, list known repos, get their names
- add tunnel to own repo, send "ping" app_call to others
- track collection for data repo and add data to it, update dht with hash
- get iroh replication for collection using app_call to tunnels n repo
- attempt to send requests to tunnels of other peers and do paralell reads for those that have the data (track dead tunnels to add to ignore list)
- standardize on ABI to invoke via FFI
- standardize on URI scheme for linking to groups
- exend uri scheme for also adding data repo keypair for migrating devices
- "backup server" listening for rpc to start replicating groups
