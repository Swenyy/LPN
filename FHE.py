#!/usr/bin/python3
# -*- coding: utf-8 -*-

import random
import math


def rabinMiller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s //= 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i += 1
                    v = (v ** 2) % num
    return True


def isPrime(num):
    if num < 2:
        return False
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
                 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
                 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
                 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
                 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
                 991, 997]

    if num in lowPrimes:
        return True
    for prime in lowPrimes:
        if num % prime == 0:
            return False

    return rabinMiller(num)


def generateLargePrime(keysize=1024):
    if keysize < 4:
        raise ValueError("keysize must be more than 4")
    else:
        while True:
            num = random.randrange(2 ** (keysize - 1), 2 ** keysize)
            if isPrime(num):
                return num


def generate_HEkeypair(keysize=1024):
    p = generateLargePrime(keysize=keysize)
    q = generateLargePrime(keysize=keysize - 2)  # p > q
    HE = HECrypt(p, q)
    return HE


class HECrypt(object):

    def __init__(self, p, q):
        if not isinstance(p, int):
            raise ValueError('Expected int type plaintext but got: %s' % type(p))
        if not isinstance(q, int):
            raise ValueError('Expected int type plaintext but got: %s' % type(q))
        self.p = p
        self.q = q

    def generate_random_r(self):
        return random.randrange(-self.p // 2, self.p // 2)

    def encrypt(self, m):
        if not isinstance(m, int):
            raise ValueError('Expected int type plaintext but got: %s' % type(m))

        if m < 0:
            raise ValueError('m shoubld be more than 0')

        if m >= self.q:
            raise ValueError('encrpt m should be less than q')

        r = self.generate_random_r()
        return (m + self.p + self.p * self.q * r)

    def decrypt(self, c):
        if not isinstance(c, int):
            raise ValueError('Expected int type plaintext but got: %s' % type(c))
        return ((c % self.p) + self.p) % self.p


def save_key(filename, key):
    try:
        if not isinstance(key, int):
            raise ValueError('Expected int type plaintext but got: %s' % type(key))

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(str(key))
    except Exception as e:
        print(e)


def load_key(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return int(f.read(-1))
    except Exception as e:
        print(e)

# if __name__ == "__main__":
