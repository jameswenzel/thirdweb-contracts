# SigMint









## Methods

### mintWithSignature

```solidity
function mintWithSignature(ISignatureMintERC721.MintRequest _req, bytes _signature) external payable returns (address signer)
```



*Claim lazy minted tokens via signature.*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _req | ISignatureMintERC721.MintRequest | undefined
| _signature | bytes | undefined

#### Returns

| Name | Type | Description |
|---|---|---|
| signer | address | undefined

### verify

```solidity
function verify(ISignatureMintERC721.MintRequest _req, bytes _signature) external view returns (bool success, address signer)
```



*Verifies that a mint request is signed by an authorized account.*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _req | ISignatureMintERC721.MintRequest | undefined
| _signature | bytes | undefined

#### Returns

| Name | Type | Description |
|---|---|---|
| success | bool | undefined
| signer | address | undefined



## Events

### TokensMintedWithSignature

```solidity
event TokensMintedWithSignature(address indexed signer, address indexed mintedTo, uint256 indexed tokenIdMinted, ISignatureMintERC721.MintRequest mintRequest)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| signer `indexed` | address | undefined |
| mintedTo `indexed` | address | undefined |
| tokenIdMinted `indexed` | uint256 | undefined |
| mintRequest  | ISignatureMintERC721.MintRequest | undefined |



