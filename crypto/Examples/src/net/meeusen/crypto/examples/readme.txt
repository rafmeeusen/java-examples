ECIES demo 

jcop project + java project

encrypt messages in jcop applet + decrypt on PC
& vice-versa 


------------------------------------------------------------
Applet usage
------------------------------------------------------------
Here’s an applet doing both encryption and decryption.

Commands:
INS 0x80: generates the keypair used to receive/decrypt messages
Input: none
Output: public key

INS 0xA0: encryption
Input: Receivers Public Key | Key Derivation Parameters | Encoding Parameters | Message
Output: Ephemeral Public Key | Ciphertext | Tag

INS 0x90: decryption
Input: Ephemeral Public Key | Key Derivation Parameters | Encoding Parameters | Ciphertext | Tag
Output: Message
SW: 9000 if Tag is correct, 6982 if Tag is incorrect

Example:
>  /send 00800000
=> 00 80 00 00                                        ....
(18286 usec)
<= 04 25 48 A8 5F A3 07 18 43 3B 3E 8E 84 2A DB D9    .%H._...C;>..*..
    84 B8 71 20 F6 E8 7E 3D F6 F6 73 14 2E B4 8F 1E    ..q ..~=..s.....
    FF 4E 0A 53 9F 6C 4E 5B A4 50 63 E0 41 13 71 42    .N.S.lN[.Pc.A.qB
    B8 52 45 96 F3 BA 85 32 3D 8C 6F 20 85 98 3B 65    .RE....2=.o ..;e
    4F 90 00                                           O..
Status: No Error

>  /send 00A00000#(#(042548A85FA30718433B3E8E842ADBD984B87120F6E87E3DF6F673142EB48F1EFF4E0A539F6C4E5BA45063E041137142B8524596F3BA85323D8C6F2085983B654F)#(|keyparams)#(encparams)#(the_message))
=> 00 A0 00 00 62 41 04 25 48 A8 5F A3 07 18 43 3B    ....bA.%H._...C;
    3E 8E 84 2A DB D9 84 B8 71 20 F6 E8 7E 3D F6 F6    >..*....q ..~=..
    73 14 2E B4 8F 1E FF 4E 0A 53 9F 6C 4E 5B A4 50    s......N.S.lN[.P
    63 E0 41 13 71 42 B8 52 45 96 F3 BA 85 32 3D 8C    c.A.qB.RE....2=.
    6F 20 85 98 3B 65 4F 09 6B 65 79 70 61 72 61 6D    o ..;eO.keyparam
    73 09 65 6E 63 70 61 72 61 6D 73 0B 74 68 65 5F    s.encparams.the_
    6D 65 73 73 61 67 65                               message
(31298 usec)
<= 41 04 0A 82 BE 66 3C DA D2 89 47 B0 4B 43 3A 59    A....f<...G.KC:Y
    A4 90 5E 44 4F A5 23 6D ED 15 E3 0D 48 E7 6D B6    ..^DO.#m....H.m.
    1E 4F 04 CF 67 BD 71 4B 5A 10 7B 80 87 5D E4 7A    .O..g.qKZ.{..].z
    E7 B8 9B 40 31 9C 87 E1 3C D1 C0 1A 90 A5 A4 E3    ...@1...<.......
    6F 79 0B 5A 13 B3 90 05 BC C6 CC F6 A8 98 14 EA    oy.Z............
    C7 CF C9 97 9C 00 EE D6 A8 83 78 54 1A 5E 4B 6A    ..........xT.^Kj
    97 DA 99 90 00                                     .....
Status: No Error

>  /send 00900000#(#(040A82BE663CDAD28947B04B433A59A4905E444FA5236DED15E30D48E76DB61E4F04CF67BD714B5A107B80875DE47AE7B89B40319C87E13CD1C01A90A5A4E36F79)#(|keyparams)#(encparams)#(|5A13B39005BCC6CCF6A898)#(EAC7CFC9979C00EED6A88378541A5E4B6A97DA99))
=> 00 90 00 00 77 41 04 0A 82 BE 66 3C DA D2 89 47    ....wA....f<...G
    B0 4B 43 3A 59 A4 90 5E 44 4F A5 23 6D ED 15 E3    .KC:Y..^DO.#m...
    0D 48 E7 6D B6 1E 4F 04 CF 67 BD 71 4B 5A 10 7B    .H.m..O..g.qKZ.{
    80 87 5D E4 7A E7 B8 9B 40 31 9C 87 E1 3C D1 C0    ..].z...@1...<..
    1A 90 A5 A4 E3 6F 79 09 6B 65 79 70 61 72 61 6D    .....oy.keyparam
    73 09 65 6E 63 70 61 72 61 6D 73 0B 5A 13 B3 90    s.encparams.Z...
    05 BC C6 CC F6 A8 98 14 EA C7 CF C9 97 9C 00 EE    ................
    D6 A8 83 78 54 1A 5E 4B 6A 97 DA 99                ...xT.^Kj...
(8375 usec)
<= 74 68 65 5F 6D 65 73 73 61 67 65 90 00             the_message..
Status: No Error
