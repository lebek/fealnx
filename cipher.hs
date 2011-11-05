import Data.Word
import Data.Bits
import Data.List
import Data.Char
import Numeric
import Data.ByteString.Internal

-- Bitwise rotate a Word8 left by 2 bits
rot2 :: Word8 -> Word8
rot2 x = rotate x 2

-- S0 internal cipher function
s0 :: Word8 -> Word8 -> Word8
s0 x1 x2 = rot2 $ x1 + x2

-- S1 internal cipher function
s1 :: Word8 -> Word8 -> Word8
s1 x1 x2 = rot2 $ x1 + x2 + 1

-- F internal cipher function
f :: [Word8] -> [Word8] -> [Word8]
f a b = [f0, f1, f2, f3]
        where j = xor (xor (a !! 1) (b !! 0)) (a !! 0)
              k = xor (xor (a !! 2) (b !! 1)) (a !! 3)
              f1 = s1 j k
              f2 = s0 k f1
              f0 = s0 (a !! 0) f1
              f3 = s1 (a !! 3) f2

-- Fk internal cipher function
fk :: [Word8] -> [Word8] -> [Word8]
fk a b = [fk0, fk1, fk2, fk3]
        where j = xor (a !! 1) (a !! 0)
              k = xor (a !! 2) (a !! 3)
              fk1 = s1 j (xor k (b !! 0))
              fk2 = s0 k (xor fk1 (b !! 1))
              fk0 = s0 (a !! 0) (xor fk1 (b !! 2))
              fk3 = s1 (a !! 3) (xor fk2 (b !! 3))

-- Convert a string to a list of Word8s
str2Wrds :: String -> [Word8]
str2Wrds = map c2w

-- Hexlify a list of Word8s
wrds2Hex :: [Word8] -> String
wrds2Hex xs = concat [ showHex a "" | a <- xs ]

-- Bitwise XOR two lists of Word8s with eachother
xorM :: [Word8] -> [Word8] -> [Word8]
xorM a b = map (\(a, b) -> xor a b) (zip a b)

-- Split a list of quads [[a,b,c,d]...] to a list of pairs [[a,b],[c,d]...]
splitQuads :: [[a]] -> [[a]]
splitQuads [] = []
splitQuads q = take 2 h : drop 2 h : splitQuads (drop 1 q)
        where h = (q !! 0)

-- Produce an extended key Ki(i=0, 1, 2, 3..., N+7) from a 128-bit key
keygen :: [Word8] -> Int -> [[Word8]]
keygen k r = take (r+8) $ splitQuads $ drop 2 ks
        where kl = splitAt 4 $ take 8 k
              kr = splitAt 4 $ drop 8 k
              qr = cycle [xorM (fst kr) (snd kr), fst kr, snd kr]
              d = zip4 ks (tail ks) (tail $ tail ks) $ tail qr
              a0 = fst kl
              b0 = snd kl
              b1 = fk a0 $ xorM b0 $ qr!!0
              ks = a0:b0:b1:[fk a $ xorM d $ xorM b q | (d, a, b, q) <- d]

-- Encrypt a 64-bit block of plaintext
encryptBlock :: [Word8] -> [[Word8]] -> Int -> [Word8]
encryptBlock p ki r = xorM (concat $ drop (r+4) ki)
                        $ concat [snd ct, xorM (fst ct) (snd ct)]
        where l0 = xorM (concat $ take 2 $ drop r ki) $ take 4 p
              r0 = xorM l0 $ xorM (concat $ take 2 $ drop (r+2) ki) $ drop 4 p
              i = (l0, r0):[ (snd lr, xorM (fst lr) (f (snd lr) k))
                        | (lr, k) <- zip i ki]
              ct = i !! r

-- Encrypt plaintext `p` under 128-bit key `k` using FEAL-NX with `n` rounds
encrypt :: String -> String -> Int -> String
encrypt p k n = concat $ e p
        where ki = keygen (str2Wrds k) n
              e "" = []
              e xs = (wrds2Hex $ encryptBlock (str2Wrds $ take 8 p) ki n)
                        : e (drop 8 xs)

-- XXX TODO more shared code between decryption and encryption function,
-- they could use the same iterator(?)

-- Decrypt 64-bit block of ciphertext
decryptBlock :: [Word8] -> [[Word8]] -> Int -> [Word8]
decryptBlock c ki r = xorM (concat $ drop r ki)
                        $ concat [snd ct, xorM (fst ct) (snd ct)]
        where rn = xorM (concat $ take 2 $ drop (r+4) ki) $ take 4 c
              ln = xorM rn $ xorM (concat $ take 2 $ drop (r+6) ki) $ drop 4 c
              i = (rn, ln):[ (snd rl, xorM (fst rl) (f (snd rl) k))
                        | (rl, k) <- zip i $ drop 8 $ reverse ki]
              ct = i !! r

-- Decrypt ciphertext `c` under 128-bit key `k` using FEAL-NX with `n` rounds
decrypt :: String -> String -> Int -> String
decrypt c k n = concat $ d c
        where ki = keygen (str2Wrds k) n
              d "" = []
              d xs = (wrds2Hex $ decryptBlock (str2Wrds $ take 8 c) ki n)
                        : d (drop 8 xs)
