-----------------------------------------------------------------------------
-- |
-- Module      :  Crypto.Skein
-- Copyright   :  (c) 2011 Felipe A. Lessa
-- License     :  BSD3 (see LICENSE)
--
-- Maintainer  :  felipe.lessa@gmail.com
-- Stability   :  provisional
-- Portability :  portable (needs FFI)
--
--
--
-----------------------------------------------------------------------------

module Crypto.Skein
    ( -- * Main hash functions
      -- ** Skein-512-512
      Skein_512_512_Ctx
    , Skein_512_512
      -- ** Skein-256-256
    , Skein_256_256_Ctx
    , Skein_256_256
      -- ** Skein-1024-1024
    , Skein_1024_1024_Ctx
    , Skein_1024_1024

      -- * Other variants
      -- $variants
      -- ** Skein-256-128
    , Skein_256_128_Ctx
    , Skein_256_128
      -- ** Skein-256-160
    , Skein_256_160_Ctx
    , Skein_256_160
      -- ** Skein-256-224
    , Skein_256_224_Ctx
    , Skein_256_224

      -- * Skein-512
      -- ** Skein-512-128
    , Skein_512_128_Ctx
    , Skein_512_128
      -- ** Skein-512-160
    , Skein_512_160_Ctx
    , Skein_512_160
      -- ** Skein-512-224
    , Skein_512_224_Ctx
    , Skein_512_224
      -- ** Skein-512-256
    , Skein_512_256_Ctx
    , Skein_512_256
      -- ** Skein-512-384
    , Skein_512_384_Ctx
    , Skein_512_384

      -- * Skein-1024
      -- ** Skein-1024-384
    , Skein_1024_384_Ctx
    , Skein_1024_384
      -- ** Skein-1024-512
    , Skein_1024_512_Ctx
    , Skein_1024_512
    ) where

-- from base
import Control.Monad (unless)
import Foreign
import Foreign.C

-- from bytestring
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU

-- from cereal
import Data.Serialize

-- from tagged
import Data.Tagged (Tagged(..))

-- from crypto-api
import Crypto.Classes

-- from this package
import Crypto.Skein.Internal


-- $variants
--
-- These hash functions produce less output bits than their state
-- size.  For example, 'Skein_512_160' produces 160 output bits
-- while having 512 bits of state size.  Their main use is to be
-- a drop-in replacement to legacy hash functions.  If you don't
-- have any special reason for using them, use one of the main
-- hash functions above (e.g. 'Skein_512_512').
--
-- You may replace:
--
--   [MD5] with 'Skein_256_128' or 'Skein_512_128'..
--
--   [SHA-1] with 'Skein_256_160' or 'Skein_512_160'.
--
--   [SHA-224] with 'Skein_256_224' or 'Skein_512_224'.
--
--   [SHA-256] with 'Skein_256_256' or 'Skein_512_256'.
--
--   [SHA-384] with 'Skein_512_384' or 'Skein_1024_384'.
--
--   [SHA-512] with 'Skein_512_512' or 'Skein_1024_512'.


-- | Helper function to create 'initialCtx'.
initialCtxSkein :: Storable internalCtx =>
                   CSize
                -> (Ptr internalCtx -> CSize -> IO CInt)
                -> (internalCtx -> externalCtx)
                -> externalCtx
initialCtxSkein bits init_ mkCtx =
    unsafePerformIO $
    alloca $ \ctx_ptr -> do
      check $ init_ ctx_ptr bits
      fmap mkCtx $ peek ctx_ptr

-- | Helper function to create 'updateCtxSkein'.
updateCtxSkein :: Storable internalCtx =>
                  (Ptr internalCtx -> Ptr Word8 -> CSize -> IO CInt)
               -> (externalCtx -> internalCtx)
               -> (internalCtx -> externalCtx)
               -> (externalCtx -> B.ByteString -> externalCtx)
updateCtxSkein update unCtx mkCtx = \ctx bs ->
    unsafePerformIO $
    BU.unsafeUseAsCStringLen bs $ \(bs_ptr, bs_len) ->
    with (unCtx ctx) $ \ctx_ptr -> do
      check $ update ctx_ptr (castPtr bs_ptr) (fromIntegral bs_len)
      fmap mkCtx $ peek ctx_ptr

-- | Helper function to create 'finalize'.
finalizeSkein :: Storable internalCtx =>
                 Int
              -> (Ptr internalCtx -> Ptr Word8 -> CSize -> IO CInt)
              -> (Ptr internalCtx -> Ptr Word8 -> IO CInt)
              -> (externalCtx -> internalCtx)
              -> (B.ByteString -> hash)
              -> (externalCtx -> B.ByteString -> hash)
finalizeSkein hashLenBytes update final unCtx mkHash = \ctx bs ->
    unsafePerformIO $
    with (unCtx ctx) $ \ctx_ptr -> do
      unless (B.null bs) $
        BU.unsafeUseAsCStringLen bs $ \(bs_ptr, bs_len) ->
          check $ update ctx_ptr (castPtr bs_ptr) (fromIntegral bs_len)
      fmap mkHash $ BI.create hashLenBytes $ check . final ctx_ptr . castPtr




----------------------------------------------------------------------
-- Skein-256
----------------------------------------------------------------------

-- | Context of the Skein-256-128 hash function.
newtype Skein_256_128_Ctx = S_256_128_Ctx {unS_256_128_Ctx :: Skein256Ctx}

-- | Skein-256-128 hash.  You probably want to use 'encode' to
-- obtain a 128-bit (16-byte) 'ByteString'.  May be used as a
-- drop-in replacement for MD5.
newtype Skein_256_128 = S_256_128 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_256_128 where
    put (S_256_128 bs) = putByteString bs
    get = fmap S_256_128 $ getByteString 16

instance Hash Skein_256_128_Ctx Skein_256_128 where
    outputLength = Tagged 128
    blockLength  = Tagged 256
    initialCtx   = initialCtxSkein 128 skein256Init S_256_128_Ctx
    updateCtx    = updateCtxSkein skein256Update unS_256_128_Ctx S_256_128_Ctx
    finalize     = finalizeSkein 16 skein256Update skein256Final unS_256_128_Ctx S_256_128


-- | Context of the Skein-256-160 hash function.
newtype Skein_256_160_Ctx = S_256_160_Ctx {unS_256_160_Ctx :: Skein256Ctx}

-- | Skein-256-160 hash.  You probably want to use 'encode' to
-- obtain a 160-bit (20-byte) 'ByteString'.  May be used as a
-- drop-in replacement for SHA-1.
newtype Skein_256_160 = S_256_160 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_256_160 where
    put (S_256_160 bs) = putByteString bs
    get = fmap S_256_160 $ getByteString 20

instance Hash Skein_256_160_Ctx Skein_256_160 where
    outputLength = Tagged 160
    blockLength  = Tagged 256
    initialCtx   = initialCtxSkein 160 skein256Init S_256_160_Ctx
    updateCtx    = updateCtxSkein skein256Update unS_256_160_Ctx S_256_160_Ctx
    finalize     = finalizeSkein 20 skein256Update skein256Final unS_256_160_Ctx S_256_160


-- | Context of the Skein-256-224 hash function.
newtype Skein_256_224_Ctx = S_256_224_Ctx {unS_256_224_Ctx :: Skein256Ctx}

-- | Skein-256-224 hash.  You probably want to use 'encode' to
-- obtain a 224-bit (28-byte) 'ByteString'.  May be used as a
-- drop-in replacement for SHA-224.
newtype Skein_256_224 = S_256_224 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_256_224 where
    put (S_256_224 bs) = putByteString bs
    get = fmap S_256_224 $ getByteString 28

instance Hash Skein_256_224_Ctx Skein_256_224 where
    outputLength = Tagged 224
    blockLength  = Tagged 256
    initialCtx   = initialCtxSkein 224 skein256Init S_256_224_Ctx
    updateCtx    = updateCtxSkein skein256Update unS_256_224_Ctx S_256_224_Ctx
    finalize     = finalizeSkein 28 skein256Update skein256Final unS_256_224_Ctx S_256_224


-- | Context of the Skein-256-256 hash function.
newtype Skein_256_256_Ctx = S_256_256_Ctx {unS_256_256_Ctx :: Skein256Ctx}

-- | Skein-256-256 hash.  You probably want to use 'encode' to
-- obtain a 256-bit (32-byte) 'ByteString'.  Usually it's better
-- to use 'Skein_512_256' (256 bits of output) or 'Skein_512_512'
-- (512 bits of output).
newtype Skein_256_256 = S_256_256 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_256_256 where
    put (S_256_256 bs) = putByteString bs
    get = fmap S_256_256 $ getByteString 32

instance Hash Skein_256_256_Ctx Skein_256_256 where
    outputLength = Tagged 256
    blockLength  = Tagged 256
    initialCtx   = initialCtxSkein 256 skein256Init S_256_256_Ctx
    updateCtx    = updateCtxSkein skein256Update unS_256_256_Ctx S_256_256_Ctx
    finalize     = finalizeSkein 32 skein256Update skein256Final unS_256_256_Ctx S_256_256




----------------------------------------------------------------------
-- Skein-512
----------------------------------------------------------------------

-- | Context of the Skein-512-128 hash function.
newtype Skein_512_128_Ctx = S_512_128_Ctx {unS_512_128_Ctx :: Skein512Ctx}

-- | Skein-512-128 hash.  You probably want to use 'encode' to
-- obtain a 128-bit (16-byte) 'ByteString'.  May be used as a
-- drop-in replacement for MD5.
newtype Skein_512_128 = S_512_128 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_512_128 where
    put (S_512_128 bs) = putByteString bs
    get = fmap S_512_128 $ getByteString 16

instance Hash Skein_512_128_Ctx Skein_512_128 where
    outputLength = Tagged 128
    blockLength  = Tagged 512
    initialCtx   = initialCtxSkein 128 skein512Init S_512_128_Ctx
    updateCtx    = updateCtxSkein skein512Update unS_512_128_Ctx S_512_128_Ctx
    finalize     = finalizeSkein 16 skein512Update skein512Final unS_512_128_Ctx S_512_128

-- | Context of the Skein-512-160 hash function.
newtype Skein_512_160_Ctx = S_512_160_Ctx {unS_512_160_Ctx :: Skein512Ctx}

-- | Skein-512-160 hash.  You probably want to use 'encode' to
-- obtain a 160-bit (20-byte) 'ByteString'.  May be used as a
-- drop-in replacement for SHA-1.
newtype Skein_512_160 = S_512_160 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_512_160 where
    put (S_512_160 bs) = putByteString bs
    get = fmap S_512_160 $ getByteString 20

instance Hash Skein_512_160_Ctx Skein_512_160 where
    outputLength = Tagged 160
    blockLength  = Tagged 512
    initialCtx   = initialCtxSkein 160 skein512Init S_512_160_Ctx
    updateCtx    = updateCtxSkein skein512Update unS_512_160_Ctx S_512_160_Ctx
    finalize     = finalizeSkein 20 skein512Update skein512Final unS_512_160_Ctx S_512_160


-- | Context of the Skein-512-224 hash function.
newtype Skein_512_224_Ctx = S_512_224_Ctx {unS_512_224_Ctx :: Skein512Ctx}

-- | Skein-512-224 hash.  You probably want to use 'encode' to
-- obtain a 224-bit (28-byte) 'ByteString'.  May be used as a drop-in replacement for SHA-224.
newtype Skein_512_224 = S_512_224 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_512_224 where
    put (S_512_224 bs) = putByteString bs
    get = fmap S_512_224 $ getByteString 28

instance Hash Skein_512_224_Ctx Skein_512_224 where
    outputLength = Tagged 224
    blockLength  = Tagged 512
    initialCtx   = initialCtxSkein 224 skein512Init S_512_224_Ctx
    updateCtx    = updateCtxSkein skein512Update unS_512_224_Ctx S_512_224_Ctx
    finalize     = finalizeSkein 28 skein512Update skein512Final unS_512_224_Ctx S_512_224


-- | Context of the Skein-512-256 hash function.
newtype Skein_512_256_Ctx = S_512_256_Ctx {unS_512_256_Ctx :: Skein512Ctx}

-- | Skein-512-256 hash.  You probably want to use 'encode' to
-- obtain a 256-bit (32-byte) 'ByteString'.
newtype Skein_512_256 = S_512_256 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_512_256 where
    put (S_512_256 bs) = putByteString bs
    get = fmap S_512_256 $ getByteString 32

instance Hash Skein_512_256_Ctx Skein_512_256 where
    outputLength = Tagged 256
    blockLength  = Tagged 512
    initialCtx   = initialCtxSkein 256 skein512Init S_512_256_Ctx
    updateCtx    = updateCtxSkein skein512Update unS_512_256_Ctx S_512_256_Ctx
    finalize     = finalizeSkein 32 skein512Update skein512Final unS_512_256_Ctx S_512_256


-- | Context of the Skein-512-384 hash function.
newtype Skein_512_384_Ctx = S_512_384_Ctx {unS_512_384_Ctx :: Skein512Ctx}

-- | Skein-512-384 hash.  You probably want to use 'encode' to
-- obtain a 384-bit (48-byte) 'ByteString'.  May be used as a
-- drop-in replacement for SHA-384.
newtype Skein_512_384 = S_512_384 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_512_384 where
    put (S_512_384 bs) = putByteString bs
    get = fmap S_512_384 $ getByteString 48

instance Hash Skein_512_384_Ctx Skein_512_384 where
    outputLength = Tagged 384
    blockLength  = Tagged 512
    initialCtx   = initialCtxSkein 384 skein512Init S_512_384_Ctx
    updateCtx    = updateCtxSkein skein512Update unS_512_384_Ctx S_512_384_Ctx
    finalize     = finalizeSkein 48 skein512Update skein512Final unS_512_384_Ctx S_512_384


-- | Context of the Skein-512-512 hash function.
newtype Skein_512_512_Ctx = S_512_512_Ctx {unS_512_512_Ctx :: Skein512Ctx}

-- | Skein-512-512 hash.  You probably want to use 'encode' to
-- obtain a 512-bit (64-byte) 'ByteString'.  It's the main Skein
-- hash function.  May be used as a drop-in replacement for
-- SHA-512 as well.
newtype Skein_512_512 = S_512_512 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_512_512 where
    put (S_512_512 bs) = putByteString bs
    get = fmap S_512_512 $ getByteString 32

instance Hash Skein_512_512_Ctx Skein_512_512 where
    outputLength = Tagged 512
    blockLength  = Tagged 512
    initialCtx   = initialCtxSkein 512 skein512Init S_512_512_Ctx
    updateCtx    = updateCtxSkein skein512Update unS_512_512_Ctx S_512_512_Ctx
    finalize     = finalizeSkein 32 skein512Update skein512Final unS_512_512_Ctx S_512_512



----------------------------------------------------------------------
-- Skein-1024
----------------------------------------------------------------------

-- | Context of the Skein-1024-384 hash function.
newtype Skein_1024_384_Ctx = S_1024_384_Ctx {unS_1024_384_Ctx :: Skein1024Ctx}

-- | Skein-1024-384 hash.  You probably want to use 'encode' to
-- obtain a 384-bit (48-byte) 'ByteString'.  May be used as a
-- drop-in replacement for SHA-384.
newtype Skein_1024_384 = S_1024_384 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_1024_384 where
    put (S_1024_384 bs) = putByteString bs
    get = fmap S_1024_384 $ getByteString 48

instance Hash Skein_1024_384_Ctx Skein_1024_384 where
    outputLength = Tagged 384
    blockLength  = Tagged 1024
    initialCtx   = initialCtxSkein 384 skein1024Init S_1024_384_Ctx
    updateCtx    = updateCtxSkein skein1024Update unS_1024_384_Ctx S_1024_384_Ctx
    finalize     = finalizeSkein 48 skein1024Update skein1024Final unS_1024_384_Ctx S_1024_384


-- | Context of the Skein-1024-512 hash function.
newtype Skein_1024_512_Ctx = S_1024_512_Ctx {unS_1024_512_Ctx :: Skein1024Ctx}

-- | Skein-1024-512 hash.  You probably want to use 'encode' to
-- obtain a 512-bit (64-byte) 'ByteString'.  May be used as a
-- drop-in replacement for SHA-512.
newtype Skein_1024_512 = S_1024_512 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_1024_512 where
    put (S_1024_512 bs) = putByteString bs
    get = fmap S_1024_512 $ getByteString 64

instance Hash Skein_1024_512_Ctx Skein_1024_512 where
    outputLength = Tagged 512
    blockLength  = Tagged 1024
    initialCtx   = initialCtxSkein 512 skein1024Init S_1024_512_Ctx
    updateCtx    = updateCtxSkein skein1024Update unS_1024_512_Ctx S_1024_512_Ctx
    finalize     = finalizeSkein 64 skein1024Update skein1024Final unS_1024_512_Ctx S_1024_512


-- | Context of the Skein-1024-1024 hash function.
newtype Skein_1024_1024_Ctx = S_1024_1024_Ctx {unS_1024_1024_Ctx :: Skein1024Ctx}

-- | Skein-1024-1024 hash.  You probably want to use 'encode' to
-- obtain a 1024-bit (128-byte) 'ByteString'.  This is the
-- ultra-conservative variant.  Even if some future attack
-- managed to break Skein-512, it's quite likely that Skein-1024
-- would remain secure.
newtype Skein_1024_1024 = S_1024_1024 B.ByteString deriving (Eq, Ord)

instance Serialize Skein_1024_1024 where
    put (S_1024_1024 bs) = putByteString bs
    get = fmap S_1024_1024 $ getByteString 128

instance Hash Skein_1024_1024_Ctx Skein_1024_1024 where
    outputLength = Tagged 1024
    blockLength  = Tagged 1024
    initialCtx   = initialCtxSkein 1024 skein1024Init S_1024_1024_Ctx
    updateCtx    = updateCtxSkein skein1024Update unS_1024_1024_Ctx S_1024_1024_Ctx
    finalize     = finalizeSkein 128 skein1024Update skein1024Final unS_1024_1024_Ctx S_1024_1024
