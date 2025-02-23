# Lost Frequencies - Crypto Challenge

![image](https://github.com/user-attachments/assets/c33f5473-64a9-4db6-806e-5ba6f3862065)
Solve by : Trendo

## Challenge Analysis
* Given a sequence of binary numbers: `111 0000 10 111 1000 00 10 01 010 1011 11 111 010 000 0`
* Challenge hints mention "dots and dashes" and "flashes"
* Name suggests frequency/signal related encoding

## Approach

### Binary Analysis
* The binary sequence is grouped in different lengths
* Could represent:
  * ASCII characters
  * Binary to text conversion
  * Most likely: Binary to Morse code conversion (due to challenge hints)

### Binary to Morse Conversion Hypothesis
* 1 might represent dash (-)
* 0 might represent dot (.)
* Spaces already separate the characters

### Converting the sequence
```
111   -> ---
0000  -> ....
10    -> -.
111   -> ---
1000  -> -...
00    -> ..
10    -> -.
01    -> .-
010   -> .-.
1011  -> -.--
11    -> --
111   -> ---
010   -> .-.
000   -> ...
0     -> .
```

### Morse Code Translation
```
--- .... -. --- -... .. -. .- .-. -.-- -- --- .-. ... .
```

Decoding this Morse code sequence gives us:
```
OHNOBINARYMORSE
```

Therefore, the flag would be:
```
KashiCTF{OHNOBINARYMORSE}
```
