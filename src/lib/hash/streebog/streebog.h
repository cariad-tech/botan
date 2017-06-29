/*
* Streebog
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_STREEBOG_H__
#define BOTAN_STREEBOG_H__

#include <botan/hash.h>

namespace Botan {

/**
* Streebog
*/
class BOTAN_DLL Streebog: public HashFunction
   {
   public:
      size_t output_length() const override { return m_output_bits / 8; }

      HashFunction* clone() const override { return new Streebog(m_output_bits); }
      void clear() override;
      std::string name() const override;
      size_t hash_block_size() const override { return 64; };

      std::unique_ptr<HashFunction> copy_state() const override;

      Streebog(size_t output_bits);
   protected:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t out[]) override;

      void compress(const uint8_t input[], bool lastblock = false);

   private:
      const size_t m_output_bits;
      uint64_t m_count;
      size_t m_position;
      secure_vector<uint8_t> m_buffer;
      secure_vector<uint64_t> m_h;
      secure_vector<uint64_t> m_S;
   };


/**
* Streebog-256
*/
class BOTAN_DLL Streebog_256 final : public Streebog
   {
   public:
      Streebog_256() : Streebog(256) {}
   };

/**
* Streebog-512
*/
class BOTAN_DLL Streebog_512 final : public Streebog
   {
   public:
      Streebog_512() : Streebog(512) {}
   };

extern const uint64_t STREEBOG_Ax[8][256];
extern const uint64_t STREEBOG_C[12][8];

}


#endif
