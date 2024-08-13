#  <center> revsite2

### Challange
```
watch ads for a free flag, with amazing data integrity(patent not pending) URL: http://litctf.org:31785/
```

<div style="display: flex; justify-content
: space-around; ">
  <a href="./index.html">index.html</a>
  <a href="./revsite.js">revsite.js</a>
  <a href="./revsite2.wasm">revsite2.wasm</a>
</div>

### Solution
We get to the site and see:
```html
watch an ad to receive flag points (you get the flag once you get 1e18 points)
```
and a button:
```html
<button onclick="getpoints();">get 1 flag point</button>
```

Looking at the source, we see the `getpoints` function.

```html
<script>
    for(let i = 33; i <= 125; i++){
        let chr = String.fromCharCode(i);
        let child = document.createElement("div");
        child.id = chr;
        child.innerHTML = chr;
        child.style.position="absolute";
        child.style.textAlign="center";
        child.style.left="1000px";
        document.getElementById("flag").appendChild(child);
    }
    let visit_ad = Module.cwrap("visit_ad", null, []);
    function getpoints(){
        window.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ", '_blank').focus();
        visit_ad();
    }
</script>	
```

It opens a rickroll and calls the `visit_ad` function.<br>
Before the function definition, the for-loop creates elements in an element with id `flag`.

```html
<div id="flag" hidden="">
    <div style="position:absolute;left:0px">L</div>
    <div style="position:absolute;left:15px">I</div>
    <div style="position:absolute;left:30px">T</div>
    <div style="position:absolute;left:45px">C</div>
    <div style="position:absolute;left:60px">T</div>
    <div style="position:absolute;left:75px">F</div>
    <div style="position:absolute;left:90px">{</div>
</div>
```
We see that the first part of the flag `LITCTF{` is already there so it is likely that the rest of the flag will get set here somehow.

#### WASM Module
There is not much more to the js, so its time to have a look at the wasm module, where the `visit_ad` is defined.<br>
First we open it in a browser to get a feel of what is its content.
```wasm
(func $visit_ad (;4;) (export "visit_ad")
    ...
    ;; load the points (click_count)
    i64.load offset=66336
    ;; load 123456789 constant and add it to the points
    i64.const 123456789
    local.set $var278
    local.get $var277
    local.get $var278
    i64.add
    ;; store the result in $var279
    local.set $var279
```
But then i realized going through this would take too much time so i went to ghidra and loaded the wasm into it.

```c
local_8 = lRam00010320 + 123456789;
```
We see the exact same piece of logic we reversed here, so we know `lRam00010320` will be our points count.<br>
```c
if (lRam00010300 == local_8) {
```
We don't know what `lRam00010300` is, so we look at where it comes from.

```wasm
i64.load   align=0x3 offset=0x10300
```
We see it is loaded from offset 0x10300, so we can double click the offset in ghidra and look at the initial value.

```
ram:00010300 15 cd 5b        int64_t    75BCD15h
```
We can retype the value at the offset to `int64_t` and we see it is `75BCD15h`, which equals `123456789` in decimal.<br> So this looks like just an integrity check, verifying that `points + 123456789 == lRam00010300`.

```c
int64_t_ram_00010300 = int64_t_ram_00010300 + 1;
```
it is incremented by one, so our assumption checks out.

```c
lRam00010308 = lRam00010308 + points * 3 * points + points * 5 + 3;
```
We calculate another value, we look at the initial value, same as we did with `lRam00010300`, and get that the initial value is `1`. And what we see is the transformation at each iteration.

```c
lRam00010310 = lRam00010310
                + points * 8 * points * points 
                + points * 3 * points
                + points * 3
                + 8;
```
We repeat the process, the initial value of `lRam00010310` is `3` and we see the tranformation for each iteration.

```c
lRam00010320 = lRam00010320 + 1;
```
And <b>after</b> the trandformations of each variable have been done, our points are increased.

```c
local_710[0] = lRam00010320;
unnamed_function_5(local_70,s_document.getElementById('pts').i_ram_000100aa,local_710);
```
After that the content of the element displaying points is updated. We could go and reverse the `unnamed_function_5` too, but we'll believe that it does what it says, at least for now.

```c
local_78 = lRam00010320 * lRam00010320 * lRam00010320 + lRam00010320 * lRam00010320 + lRam00010320 + 1;
if (int64_t_ram_00010308 == local_78) {
```
Here it looks like another integrity check.

```c
if (lRam00010320 == 1000000000000000000) {
```
And then we see the check for 10**18 points.<br>
If the check passes, we see blocks like these:
```c
// "document.getElementById('flag').hidden = false;"
import::env::emscripten_run_script(s_document.getElementById('flag')._ram_0001002d);


local_800[0] = (int)(char)((byte)(int64_t_ram_00010310 >> 1) ^ 0x75);
local_7f8 = int64_t_ram_00010310 >> 0x29 & 0x1ffU ^ 0x110;
// "document.getElementById('%c').style.left='%lldpx'"
unnamed_function_5(local_e0,s_document.getElementById('%c').st_ram_000100e6,local_800);
import::env::emscripten_run_script(local_e0);
```
First, the `flag` element is set to be visible.<br>
Then, we see that values are derived from the `int64_t_ram_00010310` variable. <br>
We can assume that `unnamed_function_5` is something like `sprintf`.

So now, we need to calculate the variable values when the point count reaches 10**18. We know the initial value, and we know the tranformation for each iteration. That sounds like maths, so we just plonk it into wolframalpha.

To calculate `lRam00010308`. We know the initial value is `1`. And the tranformation is `lRam00010308 += points ** 2 * 3 + points * 5 + 3`. So the formula will be:
[lRam00010308 calculation](https://www.wolframalpha.com/input?i2d=true&i=1+%2BSum%5B3*Power%5Bi%2C2%5D%2B+5*i+%2B3%2C%7Bi%2C0%2C10+**+18+-+1%7D%5D)

And that equals to `1000000000000000001000000000000000001000000000000000001`.


To calculate `lRam00010310`, we repeat the same process. The transformation for it is `lRam00010310 += 8 * points**3 + 3 * points ** 2 + 3 * points + 8`

So the calculation looks like: [lRam00010310 calculation](https://www.wolframalpha.com/input?i2d=true&i=3+%2BSum%5B8*i*i*i+%2B+3*i*i+%2B+3i+%2B+8%2C%7Bi%2C0%2C1000000000000000000-1%7D%5D) 

And that equals to `1999999999999999997000000000000000002000000000000000007000000000000000003`

Now that we know the values, we can write a solve script.

```python
#!/usr/bin/env python3

# values at points = 1000000000000000000
points = 1000000000000000000
lRam00010308 = 1000000000000000001000000000000000001000000000000000001
lRam00010310 = 1999999999999999997000000000000000002000000000000000007000000000000000003
local_78 = points * points * points + points * points + points + 1

flag = dict()

# integrity checks
assert lRam00010308 == local_78
assert points == 1000000000000000000
character = (lRam00010310 >> 1) ^ 0x75
offset = lRam00010310 >> 0x29 & 0x1ff ^ 0x110
flag[offset]=character & 0xff

character = (lRam00010310 >> 46) ^ 199
offset = lRam00010310 >> 0x2b & 0x1ff ^ 0x144
flag[offset]=character & 0xff

character = (lRam00010310 >> 9) ^ 0x69
offset = lRam00010310 >> 0x24 & 0x1ff ^ 0x131
flag[offset]=character & 0xff

character = (lRam00010310 >> 47) ^ 0xa7
offset = lRam00010310 >> 0x1c & 0x1ff ^ 0x1e
flag[offset]=character & 0xff

character = (lRam00010310 >> 18) ^ 0x82
offset = lRam00010310 >> 5 & 0x1ff ^ 0xd2
flag[offset]=character & 0xff

character = (lRam00010310 >> 23) ^ 6
offset = lRam00010310 >> 23 & 0x1ff ^ 0xb
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x2e) ^ 0xc5
offset = lRam00010310 >> 0x1c & 0x1ff ^ 0x2d
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x36) ^ 0x2d
offset = lRam00010310 >> 0x23 & 0x1ff ^ 0x151
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x33) ^ 0x6c
offset = lRam00010310 >> 1 & 0x1ff ^ 0x68
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x27) ^ 0xf
offset = lRam00010310 >> 0x34 & 0x1ff ^ 0x1f0
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x1e) ^ 0x16
offset = lRam00010310 >> 0x2b & 0x1ff ^ 0x1ff
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x2e) ^ 0xc4
offset = lRam00010310 >> 0x29 & 0x1ff ^ 0xbb
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x17) ^ 0x42
offset = lRam00010310 >> 0x13 & 0x1ff ^ 0x16a
flag[offset]=character & 0xff

character = (lRam00010310 >> 0xb) ^ 0xec
offset = lRam00010310 >> 0x34 & 0x1ff ^ 0x199
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x2e) ^ 0x8d
offset = lRam00010310 >> 0x18 & 0x1ff ^ 0xa8
flag[offset]=character & 0xff
        

print("document.getElementById('flag').hidden = false;")
for pos, val in flag.items():
    print(f"document.getElementById('{chr(val)}').style.left='{pos}px'")
```
Resulting in:
```js
document.getElementById('flag').hidden = false;
document.getElementById('t').style.left='270px'
document.getElementById('7').style.left='195px'
document.getElementById('i').style.left='225px'
document.getElementById('_').style.left='135px'
document.getElementById('m').style.left='210px'
document.getElementById('!').style.left='300px'
document.getElementById('5').style.left='180px'
document.getElementById('n').style.left='240px'
document.getElementById('s').style.left='105px'
document.getElementById('u').style.left='255px'
document.getElementById('0').style.left='120px'
document.getElementById('4').style.left='165px'
document.getElementById('e').style.left='285px'
document.getElementById('l').style.left='150px'
document.getElementById('}').style.left='315px'
```

And pasting it into the console on the site, result in the flag being displayed.
```
LITCTF{s0_l457minute!}
```
