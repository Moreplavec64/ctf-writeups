# Flagdle
### L3ak CTF 2025 - 11 solves

## Challange
```
Your group is on a 10 day streak! 🔥
```
flagdle [file](./flagdle).

## Solution

First I tried opening the file in ghidra, which didn't really work out, as ghidra did not recognize builtin go functions, as the binary was stripped, so there were hundreds of unnamed functions. So i decided to use ida instead, which worked out much better.

I started looking at the `main.main` function and the first thing it does, is calling the function `flagdle_flagdle_ReadConfig`.
```c
  Config = flagdle_flagdle_ReadConfig();
```

### flagdle/flagdle.ReadConfig

The functions stars by fetching some data from the url
```c
v10 = net_http__ptr_Client_Get(
          (_DWORD)off_A7CB10,
          (unsigned int)"https://meow.sylvie.fyi/static/flagdle.dat"
);
//...
response_body = *(_QWORD *)(v10 + 0x40);
content_length = *(_QWORD *)(v10 + 0x48);
```

Even though ida managed to recover function names, types were not. To recover what the offsets mean, I used go itself and the `unsafe.offsetOf` function to get the offset of fields in a struct.

```go
var r http.Response
fmt.Printf("0x%x\n", unsafe.Offsetof(r.Body))
// 0x40
```

after that the content was loaded into a buffer `All`.
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

Slices in go a represented as a struct with three fields: a pointer to the data, the length and the capacity. Even though the pseudocode does not show it well, by looking at the disassembly, we can see how is it done.

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

After the call to `io_ReadAll`, the slice is stored onto the stack from registers it was returned in. According to the [internal abi specification](https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md#function-call-argument-and-result-passing), the arguments can be either passed in register or on the stack, depending whether or not there is enough available registers.

##### Type Recovery

We see that the slice is then passed as the first argument to the `google_golang_org_protobuf_proto_Unmarshal`. Before that though, we see the call to `runtime_newobject`, which allocates a new object on the heap, which is then passed as the second argument to `google_golang_org_protobuf_proto_Unmarshal`.

Looking closer at the type that was passed to `runtime_newobject`, we discover some structure-looking data in `.rodata` section.
If we look at the [source code](https://github.com/golang/go/blob/master/src/runtime/malloc.go#L1746) of `runtime_newobject`, we see that it takes one argument of type `*_type`, which is defined in [internal/abi/type.go](https://github.com/golang/go/blob/go1.23.1/src/internal/abi/type.go#L20).

The most interesting field in the type is probably `Str`, which is a offset into a king of type name table. The table position is defined in the at runtime by the `module_data` structure, that has a field `types`, which points to the table. For details how it is resolved see [resolveNameOff](https://github.com/golang/go/blob/go1.23.1/src/runtime/type.go#L118).

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

So we then see, after retyping the data to `go_rtype`, that the `Str` field is at offset `104FCh`. I then added this to the `.rodata` base address and got.

```
.rodata:00000000007254FC                 db    1
.rodata:00000000007254FD                 db  15h
.rodata:00000000007254FE aPbEncryptedset db '*pb.EncryptedSettings',0
```

The Name structure that stores the type name starts with some metadata and length of the string and is defined [here](https://github.com/golang/go/blob/go1.23.1/src/internal/abi/type.go#L590)

##### GoReSym
I also tried using GoReSym to recover the types, but with no success. But it did not go in vain, as it did told me the version and dependencies of the binary.

```
----GoReSym----
Arch:                amd64
OS:                  linux
GoVersion            go1.23.1
Dep0.Path            google.golang.org/protobuf
Dep0.Version         v1.36.6
```











