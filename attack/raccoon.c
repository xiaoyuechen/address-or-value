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

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define MIN_CACHE_MISS_CYCLES (195)

typedef struct mapped_mem
{
  int fd;
  void *ptr;
  size_t size;
} mapped_mem;

mapped_mem *
create_mapped_mem (const char *path)
{
  int fd = open (path, O_RDONLY);
  if (fd < 0)
    {
      return 0;
    }
  size_t size = lseek (fd, 0, SEEK_END);
  void *ptr = mmap (0, size, PROT_READ, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED)
    {
      return 0;
    }

  mapped_mem *map = malloc (sizeof (*map));
  if (!map)
    {
      return 0;
    }
  map->fd = fd;
  map->ptr = ptr;
  map->size = size;
  return map;
}

void
destroy_mapped_mem (mapped_mem *mem)
{
  munmap (mem->ptr, mem->size);
  close (mem->fd);
  free (mem);
}

size_t
time_flush_reload (void *ptr)
{
}

int
main (int argc, char *argv[argc + 1])
{
  const char *lib_path = argv[1];
  const size_t offset[10];

  mapped_mem *mem = create_mapped_mem (lib_path);
  if (!mem)
    {
      exit (EXIT_FAILURE);
    }

  for (size_t i = 0; i < 10; ++i)
    {
    }

  destroy_mapped_mem (mem);
  exit (EXIT_SUCCESS);
}
