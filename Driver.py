# Driver module for RSA encryption module
# Driver runs a three part project based on textbook RSA encryption. 
# Part one allows users to test a number for primality using Fermat's primality test, where the user specifies the number of tests wanted. 
# Part two generates a random prime number for the user, where the user specifies the size of the number in bits, and the number of times to be tested for primality using Fermat's primality test. 
# Part three performs textbook RSA encryption on a message input by the user, shows user the keys involved, encrypted form of the message, and decrypts the message. It allows for the user to specify N-bit size primes to be used for key creation, 
#     and the number of times to be tested for primality in Fermat's primality test.

# To Run: input "python Driver.py" in bash console while in source folder

# Options:
# 1- Check number for primality
# 2- Generate random prime of specified size
# 3- RSA encryption of given message
# 4- Quit

#If decryption comes out incorrectly, a larger N input may be the solution

import py_compile
py_compile.compile('Driver.py')

import sys
from RSA import *
sys.setrecursionlimit(10000000)


#Prompts user in console to choose a problem to be done
def main():
    try:
        option = int(input("Input 1-4 from the following options 1 (check for primality), 2 (generate a prime), 3 (encrypt a message), or 4(to quit): "))
        print ("You chose option " , option)
    except ValueError:
        print("Please enter an integer")
        main()
    if (0 < option < 5):
        problemSelector(option)
    else:
        print ("Invalid Option, you needed to type a 1, 2, 3, or 4....")
        main()


#given user input, selects correct problem function to run
def problemSelector(option):
    if (option == 1):
        problem1()
    if (option == 2):
        problem2()
    if (option == 3):
        problem3()
    if (option == 4):
        exit()

    main()

#Asks user for positive integer N, and number of times to test it for primality K
#Outputs whether or not it is prime (the more tests, the better probability it is correct)
def problem1():
    N = 0;
    K = 0;
    while(N<=0):
        N = int(input("Choose an input N to check for primality (must be positive): "))
    while(K<=0):
        K = int(input("Choose K amount of times you want it tested (must be positive): "))
    isPrime = primality3(N, K)
    print(isPrime)

#Asks the user for N (number of bits used to create prime), and K (amount of times to test for primality)
#Outputs to console a randomly generated prime number of size N bits. The higher the number of tests, the higher probability of prime number
def problem2():
    N = 0;
    K = 0;
    while(N<=0):
        N = int(input("Choose an input size N to make binary prime number of N bits (must be positive): "))
    while(K<=0):
        K = int(input("Choose K amount of times you want it tested (must be positive): "))
    primeNum = generatePrime(N, K)
    print(primeNum)
    main()
    
#Asks the user for N (number of bits used to create prime), K (amount of times to test for primality), and M (integer to be encrypted using prime numbers generated)
#Outputs to console the RSA keys used, and encryption and subsequent decryption of M using those keys
def problem3():
    N = 0;
    K = 0;
    while(N<=0):
        N = int(input("Choose an input N to make prime number of N bits (must be positive, larger input required for encryption of longer messages): "))
    while(K<=0):
        K = int(input("Choose K amount of times you want it tested for primality (must be positive): "))
    #M = int(input("Choose integer M to be encrypted: "))
    M = (input("Choose string or integer M to be encrypted: "))
    try:
        M = int(M)
        stringFlag = 0
    except ValueError:
        M = stringToInt(M)
        stringFlag = 1
    RSA(N, K, M, stringFlag)

if __name__== "__main__":
     main()