/*
 * Copyright (C) 2022  Xiaoyue Chen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/aes.h>
#include <stddef.h>
#include <stdio.h>

const char key[16] = "sEcRet";
char in[17] = {};

int
main ()
{
  AES_KEY key_struct;
  AES_set_encrypt_key ((const unsigned char *)key, 128, &key_struct);
  for (size_t i = 0; i < 100; ++i)
    {
      AES_encrypt ((const unsigned char *)in, (unsigned char *)in,
                   &key_struct);
    }
  printf ("%s\n", in);
}
