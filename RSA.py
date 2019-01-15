#Module for RSA encryption

#Main function to be called in drivers is RSA(N, K, M, stringFlag)
#This goes through the process of generating keys given constraints, encrypting message using those keys, then printing out the keys, encrypted message, 
# and subsequently decrypted message

#Propper padding has not been done, therefore this shouldn't be used for any formal application

import random
import sys
import time
import math
import binascii
from random import *

sys.setrecursionlimit(10000000)

#Input: N (number of bits used to create prime), K (amount of times to test for primality), M (integer to be encrypted using prime numbers generated), and a binary stringFlag (flags whether or not conversion back to a string is needed for output after it is decrypted)
#Output: To console, generates public and private keys, encrypts then decrypts a string of numbers and/or characters
def RSA(N, K, M, stringFlag):
    keys = generateKeys(N, K)
    N = keys[0]
    E = keys[1]
    D = keys[2]
    print("\n\nPublic Key: N=", N, ", E=", E)
    print("Private Key: D=", D)

    encryptedInput = encrypt(M, E, N)
    print("Encrypted Input: ", encryptedInput)

    decryptedOutput = decrypt(encryptedInput, D, N)
    if stringFlag == 0:
        print("Decrypted Output: ", decryptedOutput)
    else:
        print("Decrypted Output: ", intToString(decryptedOutput))

#Converts a string (to be encrypted) into an integer by converting to the equivalent ASCII->Hex->decimal
#This is done so that we can do necessary encryption math on the message
#Input: String
#Output: Decimal equivalent Integer
def stringToInt(A):
    #encode A as ascii
    A = A.encode('ASCII')
    #convert to hex
    A = binascii.b2a_hex(A)
    #decode to plain string
    A = A.decode()
    #convert to base 16 int for use in math during encryption
    A = int(A, 16)
    return A

#Converts an integer (post decryption in this case) into a string by converting to the equivalent Decimal->Hex->ASCII
#This is done to respond with the decrypted string if we were originally given a string to encrypt, after doing encryption math on the message in integer form
#Input: Integer
#Output: ASCII equivalent string (in normal string form)
def intToString(A):
    #convert to Hexadecimal
    A = format(A, '02x')
    #convert to string
    A=str(A)
    #encode to ASCII
    A = A.encode('ASCII')
    #Convert from encoded Hex to encoded equivalent string (i.e. b'97 -> b'a')
    A = binascii.unhexlify(A)
    #decode for plain string
    A = A.decode('ASCII')
    return A

#finds greatest common denominator for given integers a and b
def gcd(a,b):
    if (zero(b) or (compare(a,b)==0)):
        return a
    if compare(a, b)==2:
        return gcd(b,a)
    else:
        return gcd(b, mod(a,b))

    
#shift bits for two's complement
def shift(A, n):
    if n == 0:
        return A
    return [0]+shift(A, n-1)

#shift bits for two's complement
def shiftOpp(A, n):
    if n == 0:
        return A
    return shiftOpp(A, n-1)+[0]

#recusively mutiplies two arrays of binary numbers (O(n^2]))
# with LSB(least significant bit) stored in index 0 
def mult(X, Y):
    if zero(Y):
        return [0]
    Z = mult(X, div2(Y))
    if even(Y):
        return add(Z, Z)
    else:
        return add(X, add(Z, Z))

#converts decimal ints X and Y to binary, multiplies them, then returns the decimal form
def Mult(X, Y):
    X1 = dec2bin(X)
    Y1 = dec2bin(Y)
    return bin2dec(mult(X1,Y1))

# test if the input binary number is 0
# we use both [] and [0, 0, ..., 0] to represent 0
def zero(X):
    if len(X) == 0:
        return True
    else:
        for j in range(len(X)):
            if X[j] == 1:
                return False
    return True

#floor of Y/2 (done by shifting 1 bit to remove lsb)
def div2(Y):
    if len(Y) == 0:
        return Y
    else:
        return Y[1:]

#If given binary number array is an even number or 0, return true, else return false
def even(X):
    if ((len(X) == 0) or (X[0] == 0)):
        return True
    else:
        return False

#Add two binary numbers (in array form)
#Return Binary result (in array form)
def add(A, B):
    A1 = A[:]
    B1 = B[:]
    n = len(A1)
    m = len(B1)
    if n < m:
        for j in range(len(B1)-len(A1)):
            A1.append(0)
    else:
        for j in range(len(A1)-len(B1)):
            B1.append(0)
    N = max(m, n)
    C = []
    carry = 0
    for j in range(N):
        C.append(exc_or(A1[j], B1[j], carry))
        carry = nextcarry(carry, A1[j], B1[j])
    if carry == 1:
        C.append(carry)
    return C

#Add 2 decimal numbers
#Return decimal result
def Add(A,B):
    return bin2dec(add(dec2bin(A), dec2bin(B)))

#Bitwise XOR
def exc_or(a, b, c):
    return (a ^ (b ^ c))

#Carry for binary addition
def nextcarry(a, b, c):
    if ((a & b) | (b & c) | (c & a)):
        return 1
    else:
        return 0 

#converts binary array to decimal form
def bin2dec(A):
    if len(A) == 0:
        return 0
    val = A[0]
    pow = 2
    for j in range(1, len(A)):
        val = val + pow * A[j]
        pow = pow * 2
    return val

#Given binary number array, reverses order (used to move Least Sig Bit to left of array)
def reverse(A):
    B = A[::-1]
    return B


def trim(A):
    if len(A) == 0:
        return A
    A1 = reverse(A)
    while ((not (len(A1) == 0)) and (A1[0] == 0)):
        A1.pop(0)
    return reverse(A1)

#Given binary numbers
# compares A and B: returns 1 if A > B, 2 if B > A and 0 if A == B
def compare(A, B):
    A1 = reverse(trim(A))
    A2 = reverse(trim(B))
    if len(A1) > len(A2):
        return 1
    elif len(A1) < len(A2):
        return 2
    else:
        for j in range(len(A1)):
            if A1[j] > A2[j]:
                return 1
            elif A1[j] < A2[j]:
                return 2
        return 0

#Given decimal numbers
# compares A and B: returns 1 if A > B, 2 if B > A and 0 if A == B
def Compare(A, B):
    return bin2dec(compare(dec2bin(A), dec2bin(B)))

#converts decimal number to binary
def dec2bin(n):
    if n == 0:
        return []
    m = n//2
    A = dec2bin(m)
    fbit = n % 2
    return [fbit] + A

#Given binary numbers recursively
# returns binary quotient and remainder when A is divided by B
#O(n^2)
def divide(X, Y):
    if zero(X):
        return ([],[])
    (q,r) = divide(div2(X), Y)
    q = add(q, q)
    r = add(r, r)
    if (not even(X)):
        r = add(r,[1])
    if (not compare(r,Y)== 2):
        #r = sub(r, Y)
        Y = bin2dec(Y)
        r = bin2dec(r)
        r = (r - Y)
        r = dec2bin(r)
        q = add(q, [1])
    return (q,r)

#Given decimal numbers
# returns decimal quotient and remainder when A is divided by B
def Divide(X, Y):
    (q,r) = divide(dec2bin(X), dec2bin(Y))
    return (bin2dec(q), bin2dec(r))


#given binary number, returns two's complement
def twosComp(A, B):
    #B in our subtract function(the one were making negative) becomes A in this function
    n = 0
    #see if we need to add 0's for two's complement
    if (len(A) < len(B)):
        n = (len(B) - len(A))
    #shift in new 0's if necessary
    newA = (shiftOpp(A, n))
    #swap 0's and 1's
    i = 0
    while i < len(newA):
        if (newA[i] == 1):
            newA[i] = 0
        elif(newA[i] == 0):
            newA[i] = 1
        i +=1
    #add in one to LSB
    i = 0
    while( i < len(newA)):
        
        if newA[i] == 0:
            newA[i] = 1
            break
        elif newA[i] == 1:
            newA[i] = 0
        i +=1
        
    return newA


#subtracts B from A and returns result (in binary)
def sub(A, B):
    #subtracts B from A
    # compare A and B outputs 1 if A > B, 2 if B > A and 0 if A == B
    compareResult = compare(A,B) 
    #if A > B, run normal subtract
    if (compareResult == 1):
        #get 2's compliment of B
        B = twosComp(B, A)
        #add 1 to MSB of B to make negative after 2's complement
        B = (B+[1])
        #add A and new 2's complement B
        result = add(A, B)
        del result[-1]
        return result
    
    #if b >a run below but with 2's comp at the end (2's comp result)
    elif (compareResult == 2):
    #get 2's compliment of B
        B = twosComp(B, A)
        #add 1 to MSB of B to make negative after 2's complement
        B = (B+[1])
        #add A and new 2's complement B
        result = add(A, B)
        del result[-1]
        #twosComp to make result negative used 2 results so it didn't change string size
        result = twosComp(result, result) 
        
    elif(compareResult == 0):
        zeroArray = A
        
        i = 0
        while( i < len(A)):
            zeroArray[i] = 0
            i +=1
        result = zeroArray

    return result  

#given to binary arrays
#returns modulo of a%b
def mod(a,b):
    a = bin2dec(a)
    b = bin2dec(b)
    result = a % b
    result = dec2bin(result)
    return result

#returns numerators of sequence added together after being multiplied by quotient that their denominator was multiplied by
def getNumerator(array, denominator):   
    #get correct numerator in sequence then add to subsequent numerator
    i = 0
    numerator = dec2bin(0)
    while( i < len(array)):
        result = divide(denominator, array[i])
        quotient = result[0]
        numerator = add(numerator, quotient) 
        i +=1
    return numerator

#returns the denominator needed for a sequence given the sequence of denominators
def getDenominator(array):
    leastComMult = dec2bin(1)
    i = 0
    while ( i < len(array)):
            leastComMult = LCM(leastComMult, array[i])
            i +=1
    return leastComMult
    

#LCM(a,b) = (a*b)/GCD(a,b)
#returns Least common multiple given a and b
def LCM(a, b):
    result = mult(a, b)
    GCD = gcd(a,b)
    result = divide(result, GCD)
    quotient = result[0]
    
    return quotient

#output: x^y mod N 
#recursive O(n^3)
def modexp(x, y, N):
    if(y == 0):
        return 1
    z = modexp(x, y//2, N)
    #if y is even
    if ((y %2) == 0):
        return (z*z % N)
    else:
        return (((z*z)*x) % N)
        
    
    
#exponentiates a^b and returns result
def exp(a,b):
    result = 1
    while 1:
        if b % 2 == 1:
            result *= a
        b = int(float(b)/ 2)
        if b == 0:
            break
        a *= a
    
    return result

#beginning of primality check
#does a simple check to make sure integer isn't divisible by 2,3,5,7
def primality3(N, K):
    a = [2,3,5,7]
    isPrime = True
    for i in range (len(a)):
        result = Divide(N, a[i])
        if ((result[0] == 1 and result[1] == 0)):
            return True
        elif ((result[0] > 1) and (result[1] ==0)):
            return False
        
    isPrime = primality2(N, K)
    return isPrime

#Iterates through primality function k times to check primality k times as requested
def primality2(N, K):
    isPrime = True
    i = 0
    while (i < K):
        isPrime = primality(N)
        if (isPrime == False):
            return False
        i = i + 1

    return isPrime

#checks primality using a random integer between 1 and (N-1)
def primality(N):
    a = randint(1, N-1)
    result = modexp(a, (N-1), N)
    if (result == 1):
        return True
    else:
        return False

#Recursive Extended Euclid
def extendedEuclid(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extendedEuclid(b % a, a)
        return (g, y - (b // a) * x, x)
       

def modInv(b, n):
    g = extendedEuclid(b, n)
    if g[0] == 1:
        return g[1] % n

#Generates prime number of requested size  (N number of bits, K number of checks for primality)
def generatePrime(N, K):
    isPrime = False
    while (isPrime == False):
        v = [0]* N
        i = 1
        while (i < (N-1)):
            v[i] = randint(0, 1)
            i = i + 1
        v[0] = 1
        v[N-1] = 1
        v = bin2dec(v)
        isPrime = primality3(v, K)
    return v

#Generate keys for RSA given requested prime number size of N bits, K number of checks for primality
def generateKeys(N, K):
    p = generatePrime(N, K)
    q = generatePrime(N, K)
    if (q == p):
        q = generatePrime(N, K)
        
    N = p*q
    e = 3
    bine = dec2bin(e)
    gcddec = 0
    a = p-1
    b = q-1
    c = dec2bin(a*b)
    while (gcddec!= 1):
        while (e < N):
            gcddd = gcd(bine, c)
            e = e + 1
            bine = dec2bin(e)
            gcddec = bin2dec(gcddd)
            if(gcddec ==1):
                eKey = e-1
                e = N
            
    D = modInv(eKey, (p-1)*(q-1))
    return(N, eKey, D)

#Input: M is integer to be encrypted, E is public key(integer), N is public key(integer)
#output: M^E mod N (encrypted input integer)
def encrypt(M, E, N):
    y = modexp(M, E, N)
    return y

#y is encrypted input using key pair that was created to go along with subsequently used D and N, D is private key(integer), N is part of public key (integer)
#output: y^D mod N (unencrypted input integer)
def decrypt(y, D, N):
    result = modexp(y, D, N)
    return result
    



