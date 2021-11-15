# The Human Method

A temptative to resurge the sun package to make a SunEC reimplementation to find vulnerabilities.

In Elliptic Curve Criptography there are two keys, one is the Private Key that is used to sign messages and as the name suggested it is a secret key, the other is the public key which is used to verify the signed messages. This system can be used to encrypt messages and verify that sender is really who pretend to be. ECC is strong enough to protect BitCoin and USA secrets, only errors in implementations of algorithms are the reason of compromised messages, like the leak of the nounce (k) used to sign a message. However I have found this interesting website https://safecurves.cr.yp.to/ that claims vulnerabilities in some curves and I have started this project.

In detail my efforts are addressed on ECDSA256 (Elliptic Curve Digital Signature Alghorithm at 256 bits) because of my previous project about [Green Certificates](https://github.com/jojo2234/GreenPass-Experiments). You can read more about my project on my medium [articles](https://medium.com/@alessandro_mazzeo/). For this reason the case study of this project is on the curve prime256v1. The aim of the project is detect the Private Key knowing the Public Key and the process used to generate it. But most important I hope it could become a valid SunEC reimplementation in Java because the sun packages have been abandoned by Oracle. 

## The curve with the static point

The chosen curve for ECDSA256 over the Green Pass is prime256v1 also called secp256r1 with this math rappresentation `y²=x³+ax+b` on modular arithmetic. The private key is a big random number that get transformed in an array of bytes.
Than the static curve called secp256r1 composed of 5 static parameters a,b,p,n and h get generated.
```
p: 115792089210356248762697446949407573530086143415290314195533631308867097853951 (prime number)
a: 115792089210356248762697446949407573530086143415290314195533631308867097853948
b: 41058363725152142129326129780047268409114441015993725554835256314039467401291
n: 115792089210356248762697446949407573529996955224135760342422259061068512044369
h: 1
```
With the curve a static point that intersect the curve is created, this point is called G and it is the starting point that with the private key allow to get the public key:
```
x: 48439561293906451759052585252797914202762949526041747995844080717082404635286
y: 36134250956749795798585127919587881956611106672985015071877198253568414405109
```
Each point on a plane is created with its coordinates x and y.

## The process to get the Public Key
Now a random number called `d` is created, this number can be written in a byte array form and it is 32 bytes. This number `d` is the Private Key. You can consider the private key a path to achive the public key.

So the next step is get the Public Key from the private. The Public Key is a point that intersect the curve too and it is generated doing `p⋅G` this operation is not a simple multiplication of two numbers, because G is a point, for this reason there are special rules which require modular arithmetic to create the Public Key called `Q`. 

In the real Java implementations, points like G are transformed in an array of long and on it is used some kind of affine transformation to get another axis and speed up the calculation which in theory to sum 2 or more points as I said before require modular arithmetic.

## The signing process

Then to sign a message another secret number called `k` is created and is multiplied for `G` (in the same strange way) to get a point `R` where its x coordinate is called `r` and it is one of the two parameters that compose a signature that are `(r,s)`. So to make it easy to understand `r=R.x` where `R=k⋅G` and `k` is a random number. Instead `s` is obtained doing `s=(k¯¹)⋅(h+r⋅d) mod p` where `h` is the SHA256 of the message. For the Green Pass the message that get digested is a byte array structured in this way: `["Signature1" as String,ProtectedHeader as ByteArray,Empty ByteArray, CBOR+KID as ByteArray]`

## The verify process

The message received contains in it the signature `(r,s)`. Regarding the Green Certificate, it is in a byte array form in DER format. On the message it's calculated the hash SHA256. Then is calculated `u` which is 
`u=(s¯¹) mod p => u = s invmod(p)` that is the module inverse of `s`. Than the `R` point is recovered doing `R=(h⋅u)⋅G+(r⋅u)⋅Q`, at this point `r` must be equal to the x coordinate of the obtained point `R`.
If it is equal than the signature is valid otherwise it's not. This process in the SunEC implementation is done with a different math method to avoid modular arithmetic.

## Ideas to take advantage of possible vulnerabilities

Getting `k` is for sure a valid system but the little amount of signatures that I own make it almost impossible and I don't know what kind of system is possible apply on many signatures to retrieve `k`. For this reason I thought to a wrong idea, that I want to write here to avoid waste of time to anyone will enter in the world of Elliptic Curves in the future. The idea was this: starting from `Q` to find all the lines that intersect the curve and the `G` point. Then project the obtained points and remake this operation for each point found for 32 times. To find the private key you must collect every angles of the lines in a graph structure and the path composed of every angle which last point lead to `G` is the private key. This idea was stupid because implementation of EC are different from theory and most important the bytes in a private key are not the angle of a line that intersect the curve.

Another thought was on a bruteforce method to guess the Private Key but the truth is that without a valid method or some secret trick is an impossible operation get the private key, because there are many combinations. 

Another idea was doing G+G+G... `d` times until `Q` comes out. However this is an exaustive research and is also a bruteforce method moreover while I was doing some experiments I realized that G+G is not 2*G in this SunEC implementation, for this reason this method is not applicable. Anyway it's still possible generate a private key of 32 byte to create a public key using the same alghorithm used by the method generateKeyPair, this method is bruteforce too. This system to generate a public key on a curve from a private key uses the class ECOperations and calls the function multiply. The private key is like a path to achive the point `Q` (public key) starting from the generation point `G`. Inside the multiply function you can see that each byte of the private key is elaborated to obtain a value in the range from 0 to 15. This operation is made two times one for the variable high `int high = (255 & s[i]) >>> 4;` and one for low `int low = 15 & s[i];` so on the same byte of the private key we can obtain two different values in the range `[0,15]`. However the private key is not 2^15 because high and low are different variables. A bruteforce attack remain not possible. Consider that the other idea that one person can think is to revert the operation from `Q` to `G` but as you can see in the code in ECOperations.java to get `G` from `Q` you need to get the private key because some variables that lead to the public key are linked with each byte of the private key. 

To conclude attacking the curve itself seems not possible. You can trust me, I've worked on this curve for more than three months. I was able to sign a custom COVID-19 Digital Certificate in my [previous deleted project](https://drive.google.com/file/d/1wVcRNKiRoLi3NrYqgbBRgkTrVeEvIGjz/view?usp=sharing) on GitHub but not with a valid private key obtained with these methods.

Using the base of my previous project I created a [file to extract the signatures](https://drive.google.com/file/d/1SOZWfuyvOeGyFTjcoeFqRKlCNwoQrXUM/view?usp=sharing) in the hope that will be helpful to find `k`.

## Rules of point addition on ECDSA

These should be the rules to make point addition:
```
p3 = (x3,y3)
x3=S²-x1-x2 mod p
y3=S(x1-x3)-y1 mod p
If p1 != p2 Than S=(y2-y1)/(x2-x1) mod p => S=(((y2-y1) mod p)⋅((x2-x1)⋅ invmod p)) mod p
If p1 == p2 Than S=((b⋅x1²)+a)/(a⋅y1) mod p => S=((((b⋅x1²)+a) mod p)⋅((a⋅y1) invmod p)) mod p
```

## Getting the Private Key knowing the nounce

The way to retrieve `d` knowing `k` is: `d=r¯¹⋅(s⋅k−h)` where `h` is the SHA256 of the message.

## Why the Human Method?

The Human Method because in the first intection of the project I had chosen to use the hand made operations with modular arithmetic.

## Pull requests
There's an exception in Key Pair generation, if you can detect and correct it I'm happy to accept a pull request.

## License
GNU GPLv3
