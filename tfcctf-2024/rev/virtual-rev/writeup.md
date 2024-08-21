#  <center> virtual-rev </center>
<center> difficulty: Hard </center>

### Challange
We get 3 files: `virtual-rev`, `flag.txt` and `Dockerfile`. 

### Solution

First looking at the dockerfile, we don't see anything interesting, just that the binary and the flag are copied to the container.

```dockerfile
COPY virtual-rev /home/ctf/virtual-rev
COPY flag.txt /home/ctf/flag.txt
```

Next, let's open the binary in Ida and see what it does.

#### Register initialization

The first thing we see is that the binary initializes the registers. It sets the registers to 0 and then calls a function `init_registers`.

```c
memset(registers, 0, sizeof(registers));
init_registers(registers);
```
```c
int __fastcall init_registers(int64_t *a1)
{
  int i; // [rsp+1Ch] [rbp-4h]
  int64_t retaddr; // [rsp+28h] [rbp+8h]

  puts("Registers initialised: ");
  for ( i = 0; i < (unsigned __int64)(registers_length - 1); ++i )
    printf("(%s) = 0x%016lx\n", (&register_names)[i], a1[i]);
  a1[7] = retaddr;
  return printf("(lip) = 0x%016lx\n", a1[7]);
}
```

Looking at the `registers_length`, we see that there are 8 registers in total. The first 7 registers are set to 0 and the last register is set to the return address of the function.

Which might not be clear from the pseudo-code, but looking at the disassembly
```asm
mov     rax, [rbp+8]
```
which loads the return address, and is later stored in our variable.

#### Input processing

Next, an input buffer is created
```c
input = (char *)malloc(32uLL);
```
with the size of 32B.
Then, we enter the main loop, where we read the input and process it.

```c
while ( 1 )
  {
    fgets(input, 31, stdin);
    ...
```

After that, the input is split on `\n` and is then proccessed.
```c
src = strtok(input, " \n");
strncpy(command, src, 16uLL);
...
inst_set1_idx = -1;
inst_set2_idx = -1;
inst_set3_idx = -1;
...
sub_555555555369(command, &inst_set1_idx);
sub_5555555553E1(command, &inst_set2_idx);
sub_555555555459(command, &inst_set3_idx);
```

We see that the command variable will contain the copy of the first 16 characters of the input. Then, the command is passed to 3 functions, which will set the indexes of the instructions in the instruction sets.

#### Instruction sets

Each function does pretty much the same thing, so we will only look at one of them.

```c
_DWORD *__fastcall sub_555555555369(const char *command, _DWORD *index_ptr)
{
  _DWORD *result; // rax
  int i; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    result = (_DWORD *)inst_set1_length;
    if ( i >= (unsigned __int64)inst_set1_length )
      break;
    if ( !strcmp(command, inst_set1[i]) )
    {
      result = index_ptr;
      *index_ptr = i;
      return result;
    }
  }
  return result;
}
```

The gist of the funcion is that it iterates over the inst_set1 array and if it finds a match, it sets the index of the instruction in the instruction set.

```c
inst_set1_length = 11;
inst_set1 = {"XZD", "STF", "QER", "LQE", "SQL","RALK", "MQZL", "LQDM", "SAMO", "XKA", "MISZ"};

inst_set2_length = 6;
inst_set2 = {"NEAZ", "MINL", "OAN", "MAZ", "NO", "BRAILA"};

inst_set3_length = 1;
inst_set3 = {"FLG"};
```

#### Instruction argument parsing
After the instruction is parsed, the arguments to the instructions are parsed. This is handled by this logic.

```c
src = strtok(0LL, ",");
if ( src )
{
  strncpy(argument, src, 3uLL);
  if ( argument[0] == ' ' )
  {
    argument_length = strlen(argument);
    memmove(argument, &argument[1], argument_length);
  }
  verify_register_name(argument, &reg1_index);
}
```

What this does is, it takes the next token up until the `,` character and stores it in the `argument` variable. If there is a leading space character, it removes it. Then, it verifies if the argument is a valid register name.

The verify_register_name function follows the same logic as the instruction set functions.

```c
registers_length = 8;
register_names = {"l0", "l1", "l2", "l3", "l4", "l5", "lax", "lip"};
```

The same logic is applied to the second argument.

```c
if ( inst_set2_idx != -1 && (reg2_index != -1 || reg1_index == -1)
  || inst_set1_idx != -1 && (reg1_index == -1 || reg2_index == -1)
  || inst_set3_idx != -1 && (reg1_index != -1 || reg2_index != -1) )
{
  puts("LUMA_ERROR (3): Invalid registers for this type of instruction!");
  exit(0);
}
```

This check verifies that a correct amount of arguments are passed to the specific instruction type. 

The first instruction set requires 2 arguments, the second instruction set requires 1 argument and the third instruction set requires no arguments.

#### Limit checking

After parsing, the usage limits are checked. The binary limits the use of each instruction to 10. It is cheked by this logic.

```c
for ( i = 0; i < inst_set1_length; ++i )
{
  if ( inst_set1_counter[i] > 10 )
  {
    puts("LUMA_ERROR (4): Due to efficiency reasons, we won't let you use the same instruction too much!");
    exit(0);
  }
}
```

Same logic is applied to the second instruction set.

#### Instruction execution

```c
++inst_set1_counter[inst_set1_idx];
        v6 = reg1_index;
        registers[v6] = (*((__int64 (__fastcall **)(int64_t, int64_t))&handlers_base + inst_set1_idx + 2))(
                          registers[reg1_index],
                          registers[reg2_index]);
```

All instruction logic handlers are stored at their respective offset from the `handlers_base` address. The first two 16 Bytes are set to 0, explaining the `+2`, and the rest are the instruction handlers.

I'll spare you the reversing of each instruction handler, and will showcase only the ones that I used in the final solve.

#### Instruction handlers

##### STF
```c
__int64 __fastcall STF_func(__int64 reg_1, __int64 reg_2)
{
  int i; // [rsp+14h] [rbp-Ch]

  for ( i = 0; reg_2 > i; ++i )
    reg_1 *= 2LL;
  return reg_1;
}
```

The STF instruction multiplies the first register by 2, `reg_2` times, which is equivalent to `SHL` instruction.

##### SQL

```c
__int64 __fastcall SQL_func(__int64 reg_1, __int64 reg_2)
{
  __int64 v5; // [rsp+10h] [rbp-10h]
  __int64 v6; // [rsp+18h] [rbp-8h]

  v5 = 0LL;
  v6 = 1LL;
  while ( reg_1 > 0 || reg_2 > 0 )
  {
    if ( reg_1 % 2 == 1 || reg_2 % 2 == 1 )
      v5 += v6;
    reg_1 /= 2LL;
    reg_2 /= 2LL;
    v6 *= 2LL;
  }
  return v5;
}
```

The `SQL` instruction performes a bitwise `OR` operation on the two registers. `v5` being the result and `v6` being the mask.

And so on...

We will find out that most, if not all, instructions have their x86 counterpart. Mapping them will help us in the final solve. After reversing all the handlers, the result table looks like this.

```python
inst_set1 = (
    "XZD",  # R1 = XOR R1 R2 # Weird XOR :shrug:
    "STF",  # R1 = SHL R1 R2
    "QER",  # R1 = SHR R1 R2
    "LQE",  # R1 = AND R1 R2
    "SQL",  # R1 = OR  R1 R2
    "RALK",  # R1 = ADD R1 R2
    "MQZL",  # R1 = SUB R1 R2
    "LQDM",  # R1 = DIV R1 R2
    "SAMO",  # R1 = MOD R1 R2
    "XKA",  # R1 = MUL R1 R2
    "MISZ",  # R1 = R2          # MOV
)

inst_set2 = (
    "NEAZ",  # R1 = ~R1
    "MINL",  # R1 = NEG R1
    "OAN",  # R1 = Clear highest set bit ??
    "MAZ",  # R1 = sign of R1
    "NO",  # R1 = R1
    "BRAILA",  # R1 = ? syscall nieco idk
)

inst_set3 = ("FLG",)
```

#### FLG instruction handler
Now the final step is to look at the `FLG` instruction handler.

```c
else
{
  print_flag(registers);
}
```
The handler is called with the pointer to registers as an argument.

```c
int __fastcall print_flag(__int64 *registers)
{
  __int64 v1; // rax
  char v3; // [rsp+17h] [rbp-9h]
  FILE *stream; // [rsp+18h] [rbp-8h]

  v1 = *registers;
  if ( registers[0] == 1337 ) {
    if ( registers[1] == 108 ) {
      if ( registers[2]; == 117 ) {
        if ( registers[3] == 109 ) {
          if ( registers[4] == 97 ) {
            stream = fopen("./flag.txt", "r");
            if ( !stream )
            {
              ...
            }
            while ( 1 )
            {
              v3 = fgetc(stream);
              if ( v3 == -1 )
                break;
              putchar(v3);
            }
            LODWORD(v1) = fclose(stream);
          }
        }
      }
    }
  }
  return v1;
}
```

So, we know that to print the flag, we need:

```python
l0 == 1337
l1 == 108
l2 == 117
l3 == 109
l4 == 97
```

Now we have all the pieces to solve this challange. We need to write a sequence of instructions that will set the registers to the correct values and then call the `FLG` instruction.

#### Solve

##### Getting a 1

As all the registers are initialized to 0, we cant do much with them, as there is no `INC` instruction. But, we can use the `lip` register. It is initialized with a an address.

```
MOV l5,lip
INV l5
ADD l5,lip
NEG l5
# l5 = 1
```
DIV didn't work for some reason, so i did a workaround using the INV instruction. This results in `l5 = 1`.

```python
goal = {
    l0: 0b010100111001,  # l0 == 1337  =  7 * 191
    l1: 0b000001101100,  # l1 == 108   =  2*2 * 3*3*3
    l2: 0b000001110101,  # l2 == 117   =  3*3 * 13
    l3: 0b000001101101,  # l3 == 109   =  109
    l4: 0b000001100001,  # l4 == 97    =  97
}
```

We have to remember that we are limited to 10 uses per instructions.

I split the needed values into their prime factors and tried to leverage their similarities.

first I build a the values of `2`, `3` and `5`. Then, I see that a `100` would be useful, as `97 = 100 - 3`, `109 = 100 + 9` and `191 = 100 + 100 - 9`.

Then i created a `9` and used that where needed and so on... You get the idea.

To be careful about the limits, I use `OR` instead of `ADD` when adding to `0` and `SHL` instead of `MUL` when multiplying by `2`.

The resulting sequence:
```yaml
MOV l5,lip
INV l5
ADD l5,lip
NEG l5
# l5 = 1
MOV lax,l5
ADD lax,lax
# lax = 2
MOV lip,lax
OR lip,l5
# lip = 3
OR l4,lip
ADD l4,lax
# l4 = 5
OR l1,lax
SHL l1,l5
# l4 = 5, l1 = 4
MUL l4,l4
MUL l4,l1
# l4 == 100
OR l3,l4
# l3 = 100
OR l0,l4
# l0 = 100
SHL l0,l5
# l0 = 200
OR l2,lip
MUL l2,l2
# l2 = 9
SUB l0,l2
# l0 = 191
SUB l4,lip
# l4 = 97 #!!!! FINAL l4 !!!!#
ADD l3,l2
# l3 = 109 #!!!! FINAL l3 !!!!#
MUL l1,l2
# l1 = 4 * 9
MUL l1,lip
# l1 = 2*2 * 3*3*3 = 108 #!!!! FINAL l1 !!!!#
MOV l5,l2
# l5 = 9
SUB l5,lax
# l5 = 7
MUL l0,l5
# l0 = 7 * 191 = 1337 #!!!! FINAL l0 !!!! #
ADD l5,lip
ADD l5,lip
# l5 = 13
MUL l2, l5
# l2 = 3*3 * 13 = 117 #!!!! FINAL l2 !!!!#
FLG 
```

Now, we just need to send this sequence to and instance of this challange and profit.

```python

#!/usr/bin/env python3

from pwn import *
from re import findall

# r = process("./virtual-rev")
r = remote('challs.tfcctf.com', 31645)
reg_data = r.recvuntil(b"-------------------------------------")

## Translations from x86 to LUMA instructions
translations = {
    'SHL': 'STF',
    'OR': 'SQL',
    'MOV': 'MISZ',
    'INV': 'NEAZ',
    'ADD': 'RALK',
    'NEG': 'MINL',
    'MUL': 'XKA',
    'SUB': 'MQZL',
    'FLG': 'FLG',
}

with open("solution.txt", "r") as f:
    content = f.read()
    instructions = findall(r"([A-Z]{2,3}) ([liaxFLGp0-9,]*)\n", content)


luma_instructions = []

for inst, args in instructions:
    if inst not in translations:
        raise Exception(f"{inst} is not translatable")

    luma_instructions.append(f'{translations[inst]} {args}'.encode())

for inst in luma_instructions:
    r.sendline(inst)

r.interactive()

r.close()
```

And we get the flag.

```bash
$ FLG
TFCCTF{70b3b426b72ed46f6595c4107797b21821757ea75a91fe887c952c03f84c0e06}
```
