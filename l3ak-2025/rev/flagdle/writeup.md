# Flagdle
### L3ak CTF 2025 - 11 Solves

## Challenge
```
Your group is on a 10 day streak! 🔥
```
flagdle [file](./flagdle).

## Solution

First, I tried opening the file in Ghidra, which didn't work because Ghidra did not recognize built-in Go functions. Since the binary was stripped, there were hundreds of unnamed functions. So I decided to use IDA instead, which worked out much better.

I started looking at the `main.main` function and the first thing it does, is calling the function `flagdle_flagdle_ReadConfig`.
```c
  Config = flagdle_flagdle_ReadConfig();
```

### flagdle/flagdle.ReadConfig

The function starts by fetching data from a URL:
```c
v10 = net_http__ptr_Client_Get(
          (_DWORD)off_A7CB10,
          (unsigned int)"https://meow.sylvie.fyi/static/flagdle.dat"
);
//...
response_body = *(_QWORD *)(v10 + 0x40);
content_length = *(_QWORD *)(v10 + 0x48);
```

Although IDA recovered function names, it did not recover types. To recover the meaning of the offsets, I used Go and the `unsafe.Offsetof` function to determine the offset of fields in a struct.

```go
var r http.Response
fmt.Printf("0x%x\n", unsafe.Offsetof(r.Body))
// 0x40
```

After that, the content was loaded into a buffer named `All`.
```c
All = io_ReadAll(response_body);
```

#### Unmarshal

```c
  buffer_capacity = v24;
  buffer = All;
  v85 = runtime_newobject((unsigned int)"`", response_content_length, v24, 0, (_DWORD)v17, v25, v26, v27, v28);
  v29 = &off_84E3E0;
  v30 = (void *)v85;
  v35 = google_golang_org_protobuf_proto_Unmarshal(
          buffer,
          response_content_length,
          v76,
          (unsigned int)&off_84E3E0,
          v85);
```

In Go, slices are represented as a struct containing a pointer to the data, the length, and the capacity. Although the pseudocode does not clearly show this, the disassembly confirms it.

```asm
0x711C00                 call    io_ReadAll
0x711C05                 test    rdi, rdi
0x711C08                 jnz     loc_711EA1
0x711C0E                 mov     [rsp+0E0h+body_capacity], rcx
0x711C13                 mov     [rsp+0E0h+body_length], rbx
0x711C18                 mov     [rsp+0E0h+body_slice_ptr], rax
0x711C20                 lea     rax, asc_793D80 ; "`"
0x711C27                 call    runtime_newobject
0x711C2C                 mov     [rsp+0E0h+var_18], rax
0x711C34                 mov     rbx, [rsp+0E0h+body_length]
0x711C39                 mov     rcx, [rsp+0E0h+body_capacity]
0x711C3E                 lea     rdi, off_84E3E0
0x711C45                 mov     rsi, rax
0x711C48                 mov     rax, [rsp+0E0h+body_slice_ptr]
0x711C50                 call    google_golang_org_protobuf_proto_Unmarshal
```

After the call to `io_ReadAll`, the slice is stored onto the stack from the registers in which it was returned. According to the [internal ABI specification](https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md#function-call-argument-and-result-passing), arguments are passed either in registers or on the stack, depending whether or not there is enough available registers.

### Type Recovery

Notice that the slice is then passed as the first argument to `google_golang_org_protobuf_proto_Unmarshal`. Before that, a call to `runtime_newobject` allocates an object on the heap, which is then passed as the second argument to `google_golang_org_protobuf_proto_Unmarshal`.

Looking closer at the type passed to `runtime_newobject`, I discovered a structure in the `.rodata` section. If we look at the [source code](https://github.com/golang/go/blob/master/src/runtime/malloc.go#L1746) of `runtime_newobject`, we see that it takes one argument of type `*_type`, defined in [internal/abi/type.go](https://github.com/golang/go/blob/go1.23.1/src/internal/abi/type.go#L20).

The most interesting field in the type is likely `Str`, an offset into a type name table. The table position is defined at runtime by the `module_data` structure, which has a `types` field pointing to the table.  For details how it is resolved see [resolveNameOff](https://github.com/golang/go/blob/go1.23.1/src/runtime/type.go#L118).

First, I added a type into IDA to look at the type structure more easily.
```c
struct go_rtype // sizeof=0x30
{
    unsigned __int64 size;
    unsigned __int64 ptrdata;
    unsigned __int32 hash;
    unsigned __int8 tflag;
    unsigned __int8 align;
    unsigned __int8 fieldAlign;
    unsigned __int8 kind;
    unsigned __int64 alg;
    unsigned __int64 gcdata;
    __int32 str;
    __int32 ptrToThis;
};
```

After retyping the data to `go_rtype`, we can see that the `Str` field is at offset `104FCh`. I then added this offset to the `.rodata` base address and got:
```
.rodata:00000000007254FC                 db    1
.rodata:00000000007254FD                 db  15h
.rodata:00000000007254FE aPbEncryptedset db '*pb.EncryptedSettings',0
```

The `Name` structure that stores the type name starts with some metadata and the length of the string. It is defined [here](https://github.com/golang/go/blob/go1.23.1/src/internal/abi/type.go#L590).

#### GoReSym
I also attempted using GoReSym to recover the types but without success. However, it did provide the version and dependencies of the binary.
```
----GoReSym----
Arch:                amd64
OS:                  linux
GoVersion            go1.23.1
Dep0.Path            google.golang.org/protobuf
Dep0.Version         v1.36.6
```

#### Unmarshal
The call to unmarshal takes a slice of bytes and a message struct. We can see that the message struct is the one returned by `runtime_newobject` and is of type `EncryptedSettings`. The only return value is an error, returned in `rax`.

Now the program is accessing fields of `EncryptedSettings`, therefore it would be useful to know its structure.

### Proto File Recovery
Fortunately, the protobuf file, or rather its internal parsed rawDesc representation, is compiled into the binary. I ended up using gdb to find its content by searching for the string `EncryptedSettings` in the binary.
```
pwndbg> search EncryptedSettings
Searching for byte: b'EncryptedSettings'
// ... type names
flagdle         0x8591f9 0x6574707972636e45 ('Encrypte')
flagdle         0x859225 0x6574707972636e45 ('Encrypte')
// ... function names from pctl
```

There were some function and type names that contained the string, but I was looking for the protobuf file that is generated when you use protoc, therefore these two stood out.

```
pwndbg> hexdump 0x8591f9-0x200 0x500
+0070 0x859069  00 00 00 00 00 00 00 0a  0d 66 6c 61 67 64 6c 65  │........│.flagdle│
+0080 0x859079  2e 70 72 6f 74 6f 22 2c  0a 06 43 65 6c 6c 49 44  │.proto",│..CellID│
+0090 0x859089  12 10 0a 03 72 6f 77 18  01 20 01 28 05 52 03 72  │....row.│...(.R.r│
+00a0 0x859099  6f 77 12 10 0a 03 63 6f  6c 18 02 20 01 28 05 52  │ow....co│l....(.R│
+00b0 0x8590a9  03 63 6f 6c 22 c5 01 0a  04 47 61 6d 65 12 16 0a  │.col"...│.Game...│
+00c0 0x8590b9  06 74 61 72 67 65 74 18  01 20 01 28 09 52 06 74  │.target.│...(.R.t│
+00d0 0x8590c9  61 72 67 65 74 12 26 0a  0e 61 6c 6c 6f 77 65 64  │arget.&.│.allowed│
+00e0 0x8590d9  47 75 65 73 73 65 73 18  02 20 01 28 05 52 0e 61  │Guesses.│...(.R.a│
+00f0 0x8590e9  6c 6c 6f 77 65 64 47 75  65 73 73 65 73 12 1c 0a  │llowedGu│esses...│
+0100 0x8590f9  09 72 6f 77 48 61 73 68  65 73 18 03 20 03 28 0c  │.rowHash│es....(.│
+0110 0x859109  52 09 72 6f 77 48 61 73  68 65 73 12 18 0a 07 66  │R.rowHas│hes....f│
+0120 0x859119  6c 61 67 4b 65 79 18 04  20 01 28 0c 52 07 66 6c  │lagKey..│..(.R.fl│
+0130 0x859129  61 67 4b 65 79 12 2d 0a  0d 66 6c 61 67 53 65 6c  │agKey.-.│.flagSel│
+0140 0x859139  65 63 74 6f 72 73 18 05  20 03 28 0b 32 07 2e 43  │ectors..│..(.2..C│
+0150 0x859149  65 6c 6c 49 44 52 0d 66  6c 61 67 53 65 6c 65 63  │ellIDR.f│lagSelec│
+0160 0x859159  74 6f 72 73 12 16 0a 06  67 61 6d 65 49 44 18 06  │tors....│gameID..│
+0170 0x859169  20 01 28 09 52 06 67 61  6d 65 49 44 22 7d 0a 06  │..(.R.ga│meID"}..│
+0180 0x859179  43 6f 6e 66 69 67 12 1b  0a 05 67 61 6d 65 73 18  │Config..│..games.│
+0190 0x859189  01 20 03 28 0b 32 05 2e  47 61 6d 65 52 05 67 61  │...(.2..│GameR.ga│
+01a0 0x859199  6d 65 73 12 1e 0a 0a 77  6f 72 64 4c 65 6e 67 74  │mes....w│ordLengt│
+01b0 0x8591a9  68 18 03 20 01 28 05 52  0a 77 6f 72 64 4c 65 6e  │h....(.R│.wordLen│
+01c0 0x8591b9  67 74 68 12 1a 0a 08 66  6c 61 67 48 61 73 68 18  │gth....f│lagHash.│
+01d0 0x8591c9  04 20 01 28 0c 52 08 66  6c 61 67 48 61 73 68 12  │...(.R.f│lagHash.│
+01e0 0x8591d9  1a 0a 08 77 6f 72 64 6c  69 73 74 18 05 20 03 28  │...wordl│ist....(│
+01f0 0x8591e9  09 52 08 77 6f 72 64 6c  69 73 74 22 ec 01 0a 11  │.R.wordl│ist"....│
+0200 0x8591f9  45 6e 63 72 79 70 74 65  64 53 65 74 74 69 6e 67  │Encrypte│dSetting│
+0210 0x859209  73 12 49 0a 0e 65 6e 63  72 79 70 74 69 6f 6e 4d  │s.I..enc│ryptionM│
+0220 0x859219  6f 64 65 18 01 20 01 28  0e 32 21 2e 45 6e 63 72  │ode....(│.2!.Encr│
+0230 0x859229  79 70 74 65 64 53 65 74  74 69 6e 67 73 2e 45 6e  │yptedSet│tings.En│
+0240 0x859239  63 72 79 70 74 69 6f 6e  4d 6f 64 65 52 0e 65 6e  │cryption│ModeR.en│
+0250 0x859249  63 72 79 70 74 69 6f 6e  4d 6f 64 65 12 10 0a 03  │cryption│Mode....│
+0260 0x859259  6b 65 79 18 02 20 01 28  0c 52 03 6b 65 79 12 22  │key....(│.R.key."│
+0270 0x859269  0a 0c 67 61 6d 65 53 65  74 74 69 6e 67 73 18 03  │..gameSe│ttings..│
+0280 0x859279  20 01 28 0c 52 0c 67 61  6d 65 53 65 74 74 69 6e  │..(.R.ga│meSettin│
+0290 0x859289  67 73 22 56 0a 0e 45 6e  63 72 79 70 74 69 6f 6e  │gs"V..En│cryption│
+02a0 0x859299  4d 6f 64 65 12 16 0a 12  45 6e 63 72 79 70 74 69  │Mode....│Encrypti│
+02b0 0x8592a9  6f 6e 4d 6f 64 65 4e 6f  6e 65 10 00 12 15 0a 11  │onModeNo│ne......│
+02c0 0x8592b9  45 6e 63 72 79 70 74 69  6f 6e 4d 6f 64 65 58 4f  │Encrypti│onModeXO│
+02d0 0x8592c9  52 10 01 12 15 0a 11 45  6e 63 72 79 70 74 69 6f  │R......E│ncryptio│
+02e0 0x8592d9  6e 4d 6f 64 65 41 45 53  10 02 42 0c 5a 0a 66 6c  │nModeAES│..B.Z.fl│
+02f0 0x8592e9  61 67 64 6c 65 2f 70 62  62 06 70 72 6f 74 6f 33  │agdle/pb│b.proto3│
+0300 0x8592f9  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
```

Using ChatGPT, I generated a proto file that, when compiled, produced the same rawdesc as the one in the binary.:
```proto
syntax="proto3";

option go_package = "flagdle/pb";

message CellID {
  int32 row = 1;
  int32 col = 2;
}

message Game {
  string target = 1;
  int32 allowedGuesses = 2;
  repeated bytes rowHashes = 3; 
  bytes flagKey = 4; 
  repeated CellID flagSelectors = 5; 
  string gameID = 6; 
}

message Config {
  repeated Game games = 1;
  int32 wordLength = 3;
  bytes flagHash = 4;
  repeated string wordlist = 5;
}

message EncryptedSettings {
  enum EncryptionMode {
    EncryptionModeNone = 0;
    EncryptionModeXOR = 1;
    EncryptionModeAES = 2;
  }

  EncryptionMode encryptionMode = 1;
  bytes key = 2;
  bytes gameSettings = 3;
}
```

I verified by running `protoc --go_out=. flagdle.proto` and checking the generated `pb.pb.go` file, that the types match.

#### EncryptedConfig Parsing
```c
  v37 = *(unsigned int *)(encrypted_config + 8); // Encryption Mode
  v40 = *(_QWORD *)(encrypted_config + 0x30); // game settings length
  v38 = *(_QWORD *)(encrypted_config + 0x28); // game settings slice
  v41 = *(_QWORD *)(encrypted_config + 0x38); // game settings capacity
```

Then, a branch is taken based on the encryption mode. I unmarshaled the data to determine the mode used. It was EncryptionModeAES, so I focused on the `2` branch.

#### AES Decryption
```c
v75 = *(_QWORD *)(encrypted_config + 0x38);  // game settings capacity
v74 = *(_QWORD *)(encrypted_config + 0x30); // game settings length
v81 = *(_QWORD *)(encrypted_config + 0x28); // game settings slice
v43 = *(_QWORD *)(encrypted_config + 0x18); // key length
cipher = crypto_aes_NewCipher(
        *(_QWORD *)(encrypted_config + 0x10), // key slice
        v43,
        *(_QWORD *)(encrypted_config + 0x20), // key capacity
        );
if ( v45 )
  goto INVALID_GAME_SETTINGS;
iv = runtime_newobject((unsigned int)&unk_73F920); // [16]uint8
// Here the value of v43 (rbx register) is the value returned from `crypto_aes_NewCipher`
// which probably passed the `cipher.Block` by value and split it into `rax` and `rbx` as its size is 16 bytes
// making `rbx` the second part of the value.
//
// The second argument to NewCBCDecrypter is the IV, in the disassembly followed by the length and capacity. 
cbc_decrypter = crypto_cipher_NewCBCDecrypter(cipher, v43, iv, 16, 16);

v83 = runtime_makeslice(
  (unsigned int)&unk_73B8C0, // _type - uint8
    v74, // length - game settings length
    v74 // capacity - game settings length
  );

// cbc_decrypter.CryptBlocks
// The arguments don't really make sense here but by the context we can tell that this is just
// cbc_decrypter.CryptBlocks(v83, v81)
(*(void (__golang **)(__int64, __int64, unsigned __int64, unsigned __int64, __int64, unsigned __int64, __int64))(cbc_decrypter + 32))(
  v43,
  v83,
  v74,
  v74,
  v81,
  v74,
  v75);
if ( !v74 )
  runtime_panicIndex(-1, v83, 0);
// This ChatGPT told me was to remove padding and I did not investigate further
v57 = *(unsigned __int8 *)(v74 + v83 - 1);
if ( v74 < v57 )
  runtime_panicSliceAcap();
v40 = v74 - v57;
v29 = &off_84E400;
v30 = &unk_A8E0C0;
unmarshal_error = google_golang_org_protobuf_proto_Unmarshal(
                    v83, // decrypted game settings
                    (int)v74 - (int)v57, // length without padding
                    v74, // capacity 
                    (unsigned int)&off_84E400, // type - protoreflect.ProtoMessage
                    (unsigned int)&unk_A8E0C0, // location
                    );
```

### flagdle/flagdle.NewGame
After the config is read and no error was encountered, the `NewGame` function is called.
```c
  v10 = flagdle_flagdle_NewGame(Config, v29, v30);
```
Within this function, global variables pointing to offsets in the parsed config are accessed. Using Go, I printed the offsets of each attribute of the `Config` struct:
```go
var r pb.Config
fmt.Printf("0x%x\n", unsafe.Offsetof(r.FlagHash)) // 0x28
fmt.Printf("0x%x\n", unsafe.Offsetof(r.Games))      // 0x8
fmt.Printf("0x%x\n", unsafe.Offsetof(r.WordLength)) // 0x20
fmt.Printf("0x%x\n", unsafe.Offsetof(r.Wordlist))   // 0x40
```

Based on this output, I renamed the offsets:
```asm
.bss:0000000000A8E0C0 GAME_SETTINGS   dq ?                    ; DATA XREF: flagdle_flagdle_ReadConfig+2C2↑o
.bss:0000000000A8E0C8 GAMES           dq ?                    ; DATA XREF: flagdle_flagdle_NewGame+24↑r
.bss:0000000000A8E0D0 GAMES_LENGTH    dq ?                    ; DATA XREF: flagdle_flagdle_NewGame+1D↑r
.bss:0000000000A8E0E0 WORD_LENGTH     dd ?                    ; DATA XREF: flagdle_flagdle_NewGame+23A↑r
.bss:0000000000A8E0E8 FLAG_HASH       dq ?                    ; DATA XREF: flagdle_flagdle__ptr_FlagdleGame_ReviewGame:loc_71320A↑r
.bss:0000000000A8E0F0 FLAG_HASH_LENGTH dq ?                   ; DATA XREF: flagdle_flagdle__ptr_FlagdleGame_ReviewGame+F9↑r
.bss:0000000000A8E100 WORD_LIST       dq ?                    ; DATA XREF: flagdle_flagdle_NewGame+71↑r
.bss:0000000000A8E108 WORD_LIST_LENGTH dq ?                   ; DATA XREF: flagdle_flagdle_NewGame+78↑r
```

This made the pseudocode easier to understand:
```c
games_length = GAMES_LENGTH;
games = GAMES;
rand_i = math_rand_Intn(GAMES_LENGTH, a2, a3, a4, a5, a6, a7, a8, a9);
if ( rand_i >= games_length )
  runtime_panicIndex(rand_i, a2, games_length);
random_game_ptr = *(_QWORD *)(games + 8 * rand_i);
```

##### Wordlist Parsing
```c
map = runtime_makemap_small();
v49 = map;
curr_word = (_QWORD *)WORD_LIST;
to_add_ctr = WORD_LIST_LENGTH;
while ( to_add_ctr > 0 )
{
  v47 = to_add_ctr;
  v53 = curr_word;
  // This method returns the pointer to where the value should be stored in the map
  // and 1 is stored there(from the type definition we know that the value is a bool), therefore a true.
  *(_BYTE *)runtime_mapassign_faststr(
                (unsigned int)"\b", // map[string]bool
                map,
                *curr_word,         // string
                curr_word[1]        // string length
              ) = 1;
  curr_word = v53 + 2;
  to_add_ctr = v47 - 1;
  LODWORD(map) = v49;
}
```

After the wordlist is parsed, the random game is further processed. I used Go to determine the offsets for each field of the `Game` struct:
```yaml
GAME
Offset of target:       - data:     0x8
                        - length:   0x10
Offset of AllowdGuesses:            0x18
Offset of RowHashes:    - data:     0x20
                        - length:   0x28
                        - cap:      0x30
Offset of FlagKey:      - data:     0x38
                        - length:   0x40
                        - cap:      0x48  
Offset of FlagSelectors - data:     0x50
                        - length:   0x58
                        - cap:      0x60
Offset of gameid:       - data:     0x68
                        - length:   0x70
```

###### Creating Flag Selectors Slice from randomGame.flagSelectors
```c
flag_selectors = *(_QWORD *)(random_game_ptr + 0x50);
v52 = flag_selectors;
flag_selectors_length = *(_QWORD *)(random_game_ptr + 0x58);
v48 = flag_selectors_length;
i = 0;
v21 = 0;
slice_being_created = 0;
v23 = 0;
while ( i < flag_selectors_length )
{
  curr_flag_selector = *(_QWORD *)(flag_selectors + 8 * i);
  v14 = v23 + 1;
  row = *(int *)(curr_flag_selector + 8);
  col = *(int *)(curr_flag_selector + 12);
  if ( v21 < v23 + 1 )
  {
    v46 = i;
    v45 = col;
    new_slice = runtime_growslice(
                  slice_being_created,
                  v14,
                  v21,
                  1,
                  (unsigned int)&flagdle_cellID_type,
                  flag_selectors,
                  flag_selectors_length
                );
    flag_selectors = v52;
    flag_selectors_length = v48;
    col = v45;
    slice_being_created = new_slice;
    v14 = v23 + 1;
    v21 = v28;
    i = v46;
  }
  new_item_offset = 16 * (v14 - 1);
  *(_QWORD *)(slice_being_created + new_item_offset) = row;
  *(_QWORD *)(slice_being_created + new_item_offset + 8) = col;
  ++i;
  v23 = v14;
}
```

Based on this, I deduced that the code performs a deep copy of the Game structure that was initially parsed as a `protoreflect.ProtoMessage`, converting it into a new structure of type `FlagdleGame`. 
The `FlagdleGame` struct is not the same as the `Game` struct, so I always referenced the NewGame method to link back to the original `Game` struct. There were some optimalizations that called offsets in the method `runtime.duffcopy` which lead to the pointers being shifted and the offsets not really match the use. I decided to ignore this and not try to map the fields of the `FlagdleGame` and just vibeguess it when I see its use. 

### flagdle/flagdle.(*FlagdleGame).Play

After the game is selected and parsed, the `Play` method is called on the `FlagdleGame` struct:
```c
  v21 = flagdle_flagdle__ptr_FlagdleGame_Play(GAME, 0);
```

```c
v10 = runtime_convTstring(flagdle_game[8]); // convert string into *string, this is basically a go way of handling vararg
*(_QWORD *)&v255 = &string_ptr_type;
*((_QWORD *)&v255 + 1) = v10;
v11 = qword_A8C708;
v260 = flagdle_game + 5;
fmt_Fprintf(
  (unsigned int)&io_writer,
  qword_A8C708, // STDIO? Not important
  (unsigned int)"Flagdle Game ID: %s\n", // format
  20, // format length
  (unsigned int)&v255, // arg (*string) pointing to the game id
  1, // length of the varargs
  1 // capacity of the varargs
);
```
This gives us the information that the game ID is on the 8th position of the `FlagdleGame` struct.
Moving further in the function, we see:
```c
current_guess_index = flagdle_game[3];
v264 = v9;
v265 = v9;
v35 = runtime_convT64((int)current_guess_index + 1, v22, v29, v23, v24, 1, v30, v31, v32, v201);
*(_QWORD *)&v264 = int_ptr_type;
*((_QWORD *)&v264 + 1) = v35;
v40 = runtime_convT64(flagdle_game[10], v22, (unsigned int)int_ptr_type, v23, v24, v36, v37, v38, v39, v202);
*(_QWORD *)&v265 = int_ptr_type;
*((_QWORD *)&v265 + 1) = v40;
fmt_Fprintf(
  (unsigned int)&io_writer,
  qword_A8C708,
  (unsigned int)"\nmove (%d/%d) > ",
  16,
  (unsigned int)&v264,
  2,
  2
);
```
logic that prints the number of the current ugess and the number of allowed guesses. We can therefore mark the `flagdle_game[3]` and `flagdle_game[10]` as such.
I also verified using gdb that the `flagdle_game[3]` is the current guess by guessing and printing the value.

Next the line input is read from the stdin.
```c
v43 = (__int64 *)runtime_newobject(&string_ptr_type);
v266 = v43;
*v43 = 0;
v263[0] = "\b";
v263[1] = v43;
fmt_Fscanln(
  (unsigned int)&off_84E420,
  qword_A8C700,
  (unsigned int)v263,
  1,
  1);
```

### flagdle/flagdle.(*FlagdleGame).MakeMove

After the input is read, the `MakeMove` function is called:
```c
 Move = flagdle_flagdle__ptr_FlagdleGame_MakeMove(
  (_DWORD)flagdle_game,
  *v266,
  v266[1]
  );
```
`flagdle_game` is passed into this function, alongside with the read input and its length as the v266 is of type `string`, and strings in go are represented as a pointer to the data and its length, so v266[1] is the length.
Looking into the function, we see that the length is compared against another field in the `FlagdleGame` struct.
```c
if ( flagdle_game[11] != a3 )
{
  v116 = v9;
  v39 = runtime_convT64(flagdle_game[11], user_input, a3, a4, a5, a6, a7, a8, a9);
  *(_QWORD *)&v116 = &int_ptr_type;
  *((_QWORD *)&v116 + 1) = v39;
  return fmt_Errorf((unsigned int)"not %d letters long", 19, (unsigned int)&v116, 1, 1, v40, v41, v42, v43);
}
```
so we can mark the `flagdle_game[11]` as the length of the word that is expected to be guessed.

Then the input is converted to uppercase and checked against the wordlist. The wordlist, previously parsed into a map, is stored in `flagdle_game[12]`, a pointer to `map[string]bool`:
```c
v12 = (_DWORD *)strings_ToUpper(user_input, guess_length, guess_length, a4, a5, a6, a7, a8, a9);
  v13 = v11;
  // flagdle_game[12] is the wordlist map.
  v14 = flagdle_game[12];
  runtime_mapaccess2_faststr((__int64)&map_string_bool_type, v14, v12);
  // v14 is rbx, the second return parameter, as in go you do `val, exists := map[key]`
  if ( !(_BYTE)v14 )
    return fmt_Errorf((unsigned int)"not in dictionary", 17, 0, 0, 0, v16, v17, v18, v19);
```

The rest of the function is quite complex, but mainly because of the way go stores register values onto the stack before a function call and then restores them after. It pollutes the pseudocode quite a bit. So I will not copy the the whole pseudocode here.

The function processes the input and compares it against the target word. 
```c
runes_of_game_target = runtime_stringtoslicerune(
                           (unsigned int)&v92,
                           *flagdle_game,
                           flagdle_game[1]);
// ...
if ( *(_DWORD *)(runes_of_game_target + 4 * current_index) == (_DWORD)curr_inp_rune )
// ...
// The program builds a slice of CellStatus values, that kinda hints at what 
// is the logic in this loop trying to achieve.
  v43 = runtime_growslice(
                  (_DWORD)v31,
                  v33,
                  v32,
                  1,
                  (unsigned int)&flagdle_CellStatus_ptr
                  // ...
                  );
  // when the runes are equal and are in the same position, they are marked with the value `3`
  // the `GREEN` cells
  *(_QWORD *)&v31[8 * v33 - 8] = 3;
  // Then the orange and gray cells are set, in the v31 slice
```

The program then stores the current guess(capitalized) into `flagdle_game[2]`, which is a slice of strings.

```c
v66 = flagdle_game[4];
v67 = flagdle_game[3] + 1;
guesses_slice = flagdle_game[2];
if ( v66 < v67 )
{
  v69 = flagdle_game[3] + 1;
  v31 = (_BYTE *)&unk_1;
  guesses_slice = runtime_growslice(
                    guesses_slice,
                    v69,
                    flagdle_game[4],
                    1,
                    (unsigned int)&string_ptr_type,
                    v55,
                  );
  v70 = flagdle_game;
  flagdle_game[4] = new_cap;
  if ( dword_AAF500 )
  {
    guesses_slice = runtime_gcWriteBarrier2(1);
    *v72 = guesses_slice;
    v72[1] = v70[2];
  }
  v70[2] = guesses_slice;
```

I did not really go very deep into this, I just verified that this is what happens.
```shell
# r9 contains the pointer to the flagdle_game struct
pwndbg> hexdump $r9
+0000 0xc00029e000  b5 ec 40 00 c0 00 00 00  05 00 00 00 00 00 00 00  │..@.....│........│
+0010 0xc00029e010  20 e0 45 00 c0 00 00 00  01 00 00 00 00 00 00 00  │..E.....│........│
+0020 0xc00029e020  02 00 00 00 00 00 00 00  30 20 01 00 c0 00 00 00  │........│0.......│
+0030 0xc00029e030  01 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  │........│........│
# we are looking for the index 2, so i hexdump 0xc00045e020
pwndbg> hexdump 0xc00045e020
+0000 0xc00045e020  28 20 47 00 c0 00 00 00  05 00 00 00 00 00 00 00  │(.G.....│........│
+0010 0xc00045e030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
+0020 0xc00045e040  20 7f 86 00 c0 00 00 00  50 7f 86 00 c0 00 00 00  │........│P.......│
+0030 0xc00045e050  00 80 86 00 c0 00 00 00  30 80 86 00 c0 00 00 00  │........│0.......│
# then i want the contents of the slice so i hexdump the pointer that the index 2 points to
pwndbg> hexdump 0xc000472028
+0000 0xc000472028  47 52 45 41 54 00 00 00  42 52 4f 4b 45 00 00 00  │GREAT...│BROKE...│
# and i see my guesses
```

So my idea was right an I will not go deeper into it.
Moving forward, I see another slice being added to, which is at `flagdle_game[5]`. It's type is `[]*flagdle.BoardRow`. I find the type from the call to the function `growSlice`, which takes a pointer to the type of the element being added.
```c
v75 = v65[7];
v76 = v65[6] + 1;
v77 = v65[5];
if ( v75 < v76 )
{
  v78 = v65[6] + 1;
  v77 = runtime_growslice(
          v77,
          v78,
          v65[7],
          // number of elements being added
          1,
          // pointer to the type of the element being added
          (unsigned int)&flagdle_BoardRow_ptr_type,
          v55,
        );
  v79 = flagdle_game;
  flagdle_game[7] = v80;
  if ( dword_AAF500 )
  {
    v77 = runtime_gcWriteBarrier2(1);
    *v81 = v77;
    v81[1] = v79[5];
  }
  v79[5] = v77;
```

I'll again verify what values are being added to the slice, the same way as with the guesses.

```
pwndbg> hexdump 0xc000094000 0x60
+0000 0xc000094000  47 00 00 00 00 00 00 00  03 00 00 00 00 00 00 00  │G.......│........│
+0010 0xc000094010  52 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  │R.......│........│
+0020 0xc000094020  45 00 00 00 c0 00 00 00  01 00 00 00 00 00 00 00  │E.......│........│
+0030 0xc000094030  41 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  │A.......│........│
+0040 0xc000094040  54 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  │T.......│........│
+0050 0xc000094050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
```

I see that the type `flagdle.BoardCell`, of which the slice is made of, consists of a `Rune` and a `CellStatus`. This also disambiguates the type `flagdle.BoardRow`, which is a slice of `flagdle.BoardCell`. I'll also make note of the types of `flagdle_game[5, 6, 7]` as they are the slice, length and capacity of the `BoardRow` slice.

At the end of the function there is this code snippet
```c
// v65[1] is the target length
if ( max_index != v65[1] )
  goto LABEL_55;
if ( !(unsigned __int8)runtime_memequal(*v65, uppercase_user_inp) )
{
  v65 = flagdle_game;
LABEL_55:
  if ( (__int64)v65[3] >= (__int64)v65[10] )
    v65[13] = 2;
  return 0;
}
flagdle_game[13] = 3
```

We know that (v65 is the `FlagdleGame` struct) that `[3]` and `[10]` are the current and max guess counts, so this indicates that the `flagdle_game[13]` could be some game status.

```c
v33 = flagdle_game[13];
if ( v33 != 1 )
  break;
// process input if 1
```

Back in the function `MakeMove`, there is this condition, which checks the state, where `1` indicates ongoing game.

```shell
1 - Ongoing
2 - Out Of Guesses, Lost
3 - Won
```

### Winning the game
After the correct target word of the game is guessed, the program gives you a "game review". 
```c
else if ( game_status == 3 ){
  // ... (print win message, color setups, etc, unimportant)
  v241 = flagdle_flagdle__ptr_FlagdleGame_ReviewGame(
             (_DWORD)flagdle_game);
  // print game review (stars)
  if ( v241 >= 4 ){
     v257 = v9;
      v175 = runtime_convTstring(v133, v242, v241, 21, (unsigned int)&v258, v171, v172, v173, v174);
      *(_QWORD *)&v257 = &string_ptr_type;
      *((_QWORD *)&v257 + 1) = v175;
      fmt_Fprintf(
        (unsigned int)&io_writer,
        qword_A8C708,
        (unsigned int)"\nimpressive performance! here, have a flag: %s\n",
        47,
        (unsigned int)&v257,
        1,
        1
      );
  }
}
```

So our goal is to get the score of 4 or more and the game will give us a flag.

### flagdle/flagdle.(*FlagdleGame).ReviewGame

```c
guesses_length = flagdle_game[3];
last_guess_index = guesses_length - 1;
if ( !guesses_length )
  runtime_panicIndex(last_guess_index, a2, 0);
last_guess_offset = 16 * last_guess_index;
last_guesses_slice = flagdle_game[2];
last_guess_length = *(_QWORD *)(last_guesses_slice + last_guess_offset + 8);
last_guess_string = *(_QWORD *)(last_guesses_slice + last_guess_offset);
if ( flagdle_game[1] != last_guess_length )   // check if the lengths of target and last guess equal
  return 0;
target_string = *flagdle_game;
if ( !(unsigned __int8)runtime_memequal(last_guess_string, *flagdle_game) )// check that they equal
  return 0;
if ( flagdle_game[3] != flagdle_game[10] )    // if not all guesses were used, return 1/5
  return 1;
v17 = flagdle_flagdle__ptr_FlagdleGame_ValidateBoard(flagdle_game);
if ( target_string )
  return 2;
if ( !v17 )
  return 2;
v23 = flagdle_flagdle__ptr_FlagdleGame_SelectFlag(flagdle_game);
if ( v28 )
  return 3;
v43 = 0;
v44 = v23;
v29 = v23;
v30 = runtime_stringtoslicebyte((unsigned int)&v42, v23, 0, a4, last_guesses_slice, v24, v25, v26, v27, v38);
crypto_md5_Sum(v30, v29, v31, a4, last_guesses_slice, v32, v33, v34, v35, v38, v40);
v41 = v39;
if ( FLAG_HASH_LENGTH != 16 )
  return 4;
if ( (unsigned __int8)runtime_memequal(&v41, FLAG_HASH) )
  return 5;
return 4;
```

The function first checks if the last guess was correct. Next, if all guesses were used, it adds a point. Then, it calls `ValidateBoard`.

#### flagdle/flagdle.(*FlagdleGame).ValidateBoard

    This function checks the `BoardRows` slice (generated during `MakeMove`) against `flagdle_game[17]`. I assume that this will contain the slice that the `Game` contains, the `RowHashes`.
```c
boardrows_length = flagdle_game[6];
expected_row_hashes_length = flagdle_game[18];
if ( boardrows_length > expected_row_hashes_length )
{
  fmt_Errorf((unsigned int)"bad board size", 14, 0, 0, 0, expected_row_hashes_length, a7, a8, a9);
  return 0;
}
else if ( boardrows_length < expected_row_hashes_length )
{
  return 0;
}
else
{
  v22 = flagdle_game[6];
  board_rows_slice = (_QWORD *)flagdle_game[5];
  i = 0;
  while ( i < boardrows_length )
  {
    curr_i = i;
    v24 = board_rows_slice;
    v14 = board_rows_slice[1];
    v15 = board_rows_slice[2];
    v23[0] = *board_rows_slice;
    v23[1] = v14;
    v23[2] = v15;
    v16 = flagdle_flagdle__ptr_BoardRow_HashRow(
            (unsigned int)v23,
            v15,
            v23[0],
            a4,
            (_DWORD)board_rows_slice,
            expected_row_hashes_length,
          );
    if ( curr_i >= flagdle_game[18] )
      runtime_panicIndex(curr_i, v15, flagdle_game[18]);
    expected_row_hashes = flagdle_game[17];
    a4 = 3 * curr_i;
    v18 = *(_QWORD *)(expected_row_hashes + 24 * curr_i + 8);
    v19 = *(_QWORD *)(expected_row_hashes + 24 * curr_i);
    if ( v18 != v15 || !(unsigned __int8)runtime_memequal(v16, v19) )
      return 0;
    board_rows_slice = v24 + 3;
    i = curr_i + 1;
    boardrows_length = v22;
  }
  return 1;
}
```

The function itself is quite straightforward, it iterates over the `BoardRows`, hashes each item and compares it with the `RowHashes`.

#### Flagdle/flagdle.(*FlagdleGame).HashRow
```c
slice = *slice_ptr;
length = slice_ptr[1];
v11 = 0;
slice_built = 0;
curr_i = 0;
while ( length > 0 )
{
  ++curr_i;
  val_to_be_added = *(_QWORD *)(slice + 8);
  if ( v11 < curr_i )
  {
    v29 = length;
    v31 = slice;
    v28 = *(_QWORD *)(slice + 8);
    a4 = 1;
    new_slice = runtime_growslice(
                  slice_built,
                  curr_i,
                  v11,
                  1,
                  (unsigned int)&uint8_ptr_type,
                  length,
                  val_to_be_added,
                );
    slice = v31;
    length = v29;
    LOBYTE(val_to_be_added) = v28;
    a5 = v16;
    slice_built = new_slice;
    v11 = a5;
  }
  *(_BYTE *)(curr_i + slice_built - 1) = val_to_be_added;
  slice += 16;
  --length;
}
v27 = v11;
v30 = slice_built;
v32 = (_OWORD *)runtime_newobject(&uint_16_elem_slice_ptr_type);
crypto_md5_Sum(v30, curr_i, v27, a4, a5, v17, v18, v19, v20, v22, v24);
result = v32;
*v32 = v23;
return result;
```

So what it basically does is, that it builds a slice of bytes, that are the `CellStatus` values of the `BoardRow` items. Then it passes the slice to the `crypto_md5_Sum` function, which hashes the slice and returns the hash in a new slice of type `[16]uint8`.

#### flagdle/flagdle.(*FlagdleGame).SelectFlag

`SelectFlag` iterates over the `flagSelectors` slice, a slice of `CellID` structs (each composed of a `Row` and `Column`). These values are used to access  the `BoardRow` slice to retrieve the Row-th `BoardRow` and the Column-th `BoardCell` in that row. The `Rune` value from the `BoardCell` is XORed with the corresponding byte in the `FlagKey`. 

For 5*, also the `FlagHash` must match the selected flag. 

### Summary

To get the flag, we need to:
 - Provide `AllowedGuesses` number of guesses
 - Each i-th guess must match the i-th `RowHash`
 - The last guess must match the `Target` word
 - The values selected by the `FlagSelectors` XORed with the `FlagKey` must produce a hash that matches the `FlagHash`

#### Annotated FlagdleGame Struct
Throughout the reversing I was keeping some notes of offsets, the most important I think was the `FlagdleGame`, which in the end looked like this:
```c
flagdle_game[0]  // Game target (string)
flagdle_game[1]  // Game target length
flagdle_game[2]  // guess strings slice
flagdle_game[3]  // guess strings length (current guess index)
flagdle_game[4]  // guess strings capacity
flagdle_game[5]  // slice of boardrow ([]BoardCell)
flagdle_game[6]  // boardrows length
flagdle_game[7]  // boardrows capacity
flagdle_game[8]  // gameId (string)
flagdle_game[9]  // gameId length
flagdle_game[10] // index of the last guess
flagdle_game[11] // expected guess length
flagdle_game[12] // wordlist_map ptr - *map[string]bool
flagdle_game[13] // game status 
flagdle_game[14] // flag selectors
flagdle_game[15] // flag selectors length
flagdle_game[16] // flag selectors capacity
flagdle_game[17] // expected row hashes
flagdle_game[18] // expected row hashes length
flagdle_game[19] // expected row hashes capacity
flagdle_game[20] 
flagdle_game[21] 
```

## Solution

First, I'll need to generate the go file from the proto file using `protoc` and then unmarshal the `EncryptedSettings`. Then, decrypt them and parse the decrypted config.

To get the flag, I need to satisfy all the game review conditions. First I need to create mappings between the `RowHash` and board states. Then I need to enumerate the wordlist and find all words that, given a specific game, match the specified `RowHash`. Having this information, I'll be able to produce a set of characters, that could be the i-th XOR key for the i-th character of the flag.

But that would not work straight-forward, as there are often many possibilities for the i-th XOR key character. But I noticed that sometimes there is only one possibility. So I can enumerate all games, and for each position find the set of possible characters.

I could do that because each i-th character of the flag was encoded using a combination of the flagSelector which was a guess index and a column index. Therefore by reversing the rowHash for the for the given selector.row, I could then enumerate the wordlist and build a set of characters that the guess[selector.column] could be. And I repeated this for each character of the flag, for each game.

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"pb/pb"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
)

func main() {
  // Fetch the encrypted settings file
	resp, err := http.Get("https://meow.sylvie.fyi/static/flagdle.dat")
	if err != nil {
		panic(fmt.Errorf("http error: %w", err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("read error: %w", err))
	}

	// Unmarshal encrypted settings
	settings := &pb.EncryptedSettings{}
	if err := proto.Unmarshal(body, settings); err != nil {
		panic(fmt.Errorf("unmarshal error: %w", err))
	}

  // Check if the encryption mode is AES
	if settings.EncryptionMode != pb.EncryptedSettings_EncryptionModeAES {
		panic("NOT AES")
	}

	block, err := aes.NewCipher(settings.Key)
	if err != nil {
		panic(err)
	}

	// Decrypt AES
	iv := make([]byte, 16)
	decrypted := make([]byte, len(settings.GameSettings))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, settings.GameSettings)
	// Remove padding
	padLen := int(decrypted[len(decrypted)-1])
	configBytes := decrypted[:len(decrypted)-padLen]

	// Unmarshal decrypted config
	var cfg = &pb.Config{}
	if err := proto.Unmarshal(configBytes, cfg); err != nil {
		panic(fmt.Errorf("failed to parse decrypted protobuf: %w", err))
	}

	reverse_hashes(cfg)
}

// reverse mapping of the RowHash
var hash_to_row_state_map = make(map[string][]byte)

// generate all possible row states and fill the `hash_to_row_state_map`
// with the mapping of the hash to the row state
func generate_hash_to_state_map() {
	values := []byte{0x1, 0x2, 0x3}
	var current [5]byte

	for a := range 3 {
		current[0] = values[a]
		for b := range 3 {
			current[1] = values[b]
			for c := range 3 {
				current[2] = values[c]
				for d := range 3 {
					current[3] = values[d]
					for e := range 3 {
						current[4] = values[e]

						hash := md5.Sum(current[:])
						hashStr := hex.EncodeToString(hash[:])
						sliceCopy := slices.Clone(current[:])
						hash_to_row_state_map[hashStr] = sliceCopy
					}
				}
			}
		}
	}
}

var row_state_to_words_map map[[5]byte][]string = make(map[[5]byte][]string)

// enumerate all words, for each word and a given solution
// to the current game, calculate the row_state and
// add it into the
func generate_row_state_to_words_map(cfg *pb.Config, solution string) {
	clear(row_state_to_words_map)
	for _, word := range cfg.Wordlist {
		var result [5]byte = [5]byte{0x1, 0x1, 0x1, 0x1, 0x1}
		var used [5]bool = [5]bool{false, false, false, false, false}

		// greens
		for i := range 5 {
			if word[i] == solution[i] {
				result[i] = 0x3 // green
				used[i] = true
			}
		}

		// Second pass: find yellows
		for i := range 5 {
			if result[i] != 0x1 {
				continue // already green
			}
			for j := range 5 {
				if !used[j] && word[i] == solution[j] {
					result[i] = 0x2 // yellow
					used[j] = true
					break
				}
			}
		}

		if _, exists := row_state_to_words_map[result]; !exists {
			row_state_to_words_map[result] = []string{}
		}

		row_state_to_words_map[result] = append(row_state_to_words_map[result], word)
	}
}

// Look at each option for a give position and a flag selector and
// create a string that contains all distinct letters that the flagselector can yield
func generate_options(options []string, col int32) string {
	result := ""
	for _, option := range options {
		if strings.Contains(result, option[col:col+1]) {
			continue
		}
		result = result + option[col:col+1]
	}
	return result
}

type pos_option struct {
	options  string
	flag_key []byte
}

var pos_options map[int]*pos_option = make(map[int]*pos_option)

func reverse_hashes(cfg *pb.Config) {
  // Initialize the row_hash to state slice map
	generate_hash_to_state_map()

  // Enumerate all games, for each games solution, generate the row_state to words map
  // that groups all words that yield the same row state
	for _, game := range cfg.Games {
		generate_row_state_to_words_map(cfg, game.Target)
		options := make([][]string, len(game.RowHashes))

    // For each row hash, find the corresponding row state and all the word possibilities that 
    // yield that row state and store them in the options slice
		for i, hash := range game.RowHashes {
			needed_combination := hash_to_row_state_map[hex.EncodeToString(hash[:])]
			options[i] = row_state_to_words_map[([5]byte(needed_combination))]
		}

		for i, selector := range game.FlagSelectors {
			row := options[selector.Row]
			possibilities := generate_options(row, selector.Col)
			// Update the possibilities for i-th flag position if a game with less posibilities for
			// the given selector was found
			if existing_posibilities, exists := pos_options[i]; !exists || len(existing_posibilities.options) > len(possibilities) {
				pos_options[i] = &pos_option{options: possibilities, flag_key: game.FlagKey}
			}
		}
	}

	// Print flag
	for i := range len(pos_options) {
		v := pos_options[i]
		fmt.Printf("%c", v.flag_key[i]^v.options[0])
	}
}

```


