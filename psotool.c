#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int u32;

/////////////////////
u8 *data;
int size;

/////////////////////
static u32 keys[58];
static u8 shuffle_encrypt[256];
static u8 shuffle_decrypt[256];

void pso_decrypt(u8*dst, u8* data, u32 length, u32 key);
/////////////////////

#define PRIME_MAX (9592)
static u32 primes[PRIME_MAX];
#define PRIME_IDX0 (25)
#define PRIME_IDX1 (168)
#define PRIME_IDX2 (1229)
#define PRIME_IDX1_LEN (1061)
#define PRIME_IDX2_LEN (8353)

static const u8 sn_to_num[16] = { 0x5, 0xA, 0x7, 0x6, 0xD, 0x2, 0xC, 0x1, 0xF, 0x0, 0x8, 0xB, 0x3, 0xE, 0x9, 0x4 };
static const u8 num_to_sn[16] = { 0x9, 0x7, 0x5, 0xC, 0xF, 0x0, 0x3, 0x2, 0xA, 0xE, 0x1, 0xB, 0x6, 0x4, 0xD, 0x8 };
static const char regions[][8] = { "Japan", "USA", "Euro" };

////////////////////// Checksums related stuff
static u32 _crc32[256];

static void crc32_init(void)
{
	u32 rem;
	u8 b = 0;
	do {
		rem = b;
		for (u32 bit = 8; bit > 0; --bit) {
			if (rem & 1)
				rem = (rem >> 1) ^ 0xEDB88320;
			else
				rem = (rem >> 1);
		}
		_crc32[b] = rem;
	} while (0 != ++b);
}

static u32 crc32(const u8 *buf, u32 len)
{
#define DO1 crc = _crc32[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8)
#define DO8 DO1; DO1; DO1; DO1; DO1; DO1; DO1; DO1
	u32 crc = 0xffffffffUL;
	while (len >= 8) {
		DO8;
		len -= 8;
	}
	if (len) do {
		DO1;
	} while (--len);
	return crc ^ 0xffffffffUL;
#undef DO8
#undef DO1
}

u16 crc16(u8* buf, u32 len)
{
	u16 crc = 0;
	while (len--) {
		crc ^= *buf++ << 8;
		for (int i = 0; i < 8; i++)
			crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
	}
	return crc;
}

void fix_vmu_crc(u8 *data)
{
	*(u16*)&data[0x46] = 0;
	u32 dsize = *(u32*)&data[0x48] + 0x200 * *(u16*)&data[0x40] + 0x80;
	*(u16*)&data[0x46] = crc16(data, dsize);
}

static void make_crc(u8 *data, int len)
{
	*(u32*)data = 0;
	*(u32*)data = crc32(data, len);
}

static u32 check_crc(u8 *d, int len)
{
	// it looks like game have copy&paste bug, guild file CRC uses same range as main data
	if (len > 0x16fc) // looks like it's guild file, need to fix lenght
	{
		if (data[3] == 0x2f)
			len = 0x1550; // V1
		else
			len = 0x16fc; // V2
	}
	u32 ocrc = *(u32*)d;
	*(u32*)d = 0;
	u32 crcc = crc32(d, len);
	*(u32*)d = ocrc;
	return (crcc == ocrc) ? 1 : 0;
}

u32 guess_size(u8 *data, u32 len)
{
	if (len < 0x1700) // main data file
		return len;
	return 0x3214; // guild file, same len for V1 and V2
}

///////////////////////////////// SN check/gen/brute

static u32 IsPrime(u32 num) {
	for (u32 i = 2; i < num; i++)
		if ((num % i) == 0)
			return 0;
	return 1;
}

static void prime_gen()
{
	for (u32 i = 0, prime = 2; i < PRIME_MAX; i++) {
		primes[i] = prime;
		prime++;
		while (!IsPrime(prime))
			prime++;
	}
}

void check_sn(u32 sn)
{
	for (u32 i = 0; i < 32; i+=4) {
		sn = (sn & ~(0xf << i)) |
			sn_to_num[(sn >> i) & 0xf] << i;
	}
	printf("Plain number: 0x%08X\n", sn);
	u32 ok = 0;

	for (int rv = 0; rv < (3 * 3); rv++)
	{
		int ridx = PRIME_IDX0 + (rv / 3) + ((rv % 3) * 30);
		for (int idx1 = 0; idx1 < PRIME_IDX1_LEN; idx1++)
			for (int idx2 = 0; idx2 < PRIME_IDX2_LEN; idx2++)
			{
				u32 num = primes[ridx] * primes[idx1 + PRIME_IDX1] * primes[idx2 + PRIME_IDX2];
				if (num == sn)
				{
					printf("SN valid: PSO Ver %d %s (idx1 %d idx2 %d)\n", rv / 3 + 1, regions[rv % 3], idx1, idx2);
					ok++;
				}
			}
	}
	if (ok == 0)
		printf("SN invalid or from unknown game version\n");
}

void gen_sn()
{
	srand((u32)time(NULL));
	int idx1 = rand() % PRIME_IDX1_LEN;
	int idx2 = rand() % PRIME_IDX2_LEN;
	for (int v = 0; v < 2; v++)
		for (int r = 0; r < 3; r++)
		{
			u32 sn = primes[PRIME_IDX0 + r * 30 + v] * primes[idx1 + PRIME_IDX1] * primes[idx2 + PRIME_IDX2];
			for (u32 i = 0; i < 32; i += 4) {
				sn = (sn & ~(0xf << i)) |
					num_to_sn[(sn >> i) & 0xf] << i;
			}
			printf("%08X PSO Ver %d %s\n", sn, v + 1, regions[r]);
		}
}

u32 brute(u8* dptr, u32 dsize)
{
	time_t t;
	time(&t);
	u32 kk = 0, k = 0;
	u8* buf = malloc(dsize);

	u32 ver = -1;
	if (dsize == 0x16fc)
		ver = 1;
	else if (dsize == 0x1550)
		ver = 0;

	if (ver != -1) // main file
	{
		for (int idx1 = 0; idx1 < PRIME_IDX1_LEN; idx1++)
		{
			for (int idx2 = 0; idx2 < PRIME_IDX2_LEN; idx2++)
			{
				for (int r = 0; r < 30 * 3; r += 30)
				{
					u32 sn = primes[PRIME_IDX0 + ver + r] * primes[idx1 + PRIME_IDX1] * primes[idx2 + PRIME_IDX2];
					for (u32 i = 0; i < 32; i += 4) {
						sn = (sn & ~(0xf << i)) |
							num_to_sn[(sn >> i) & 0xf] << i;
					}

					pso_decrypt(buf, dptr, dsize, sn);
					if (*(u32*)&buf[0x340] == 0 && *(u32*)&buf[0x344] == 0 && *(u32*)&buf[0x348] == 0) // a bit hacky but makes things faster
					{
						u32 crcres = check_crc(buf, dsize);
						if (crcres) {
							printf("Key found: %08X\n", sn);
							free(buf);
							return sn;
						}
						else
							printf("Possible key %08X\n", sn);
					}
					time_t newt;
					time(&newt);
					if (difftime(newt, t) >= 10.) {
						printf("checking %02d%% kps %d\n", (k * 100) / (PRIME_IDX1_LEN*PRIME_IDX2_LEN * 3), (k - kk) / 10);
						t = newt;
						kk = k;
					}
					k++;
				}
			}
		}
	}
	else // Guild file
	{
		for (int idx1 = 0; idx1 < PRIME_IDX1_LEN; idx1++)
		{
			for (int idx2 = 0; idx2 < PRIME_IDX2_LEN; idx2++)
			{
				for (int r = 0; r < 30 * 3; r += 30)
				{
					for (int ver = 0; ver < 2; ver++) // ver is not known for guild data
					{
						u32 sn = primes[PRIME_IDX0 + ver + r] * primes[idx1 + PRIME_IDX1] * primes[idx2 + PRIME_IDX2];
						for (u32 i = 0; i < 32; i += 4) {
							sn = (sn & ~(0xf << i)) |
								num_to_sn[(sn >> i) & 0xf] << i;
						}

						pso_decrypt(buf, dptr, dsize, sn);
						if (*(u32*)&buf[0x340] == 0 && *(u32*)&buf[0x344] == 0 && *(u32*)&buf[0x348] == 0) // FIXME not confirmed for well used guild data
						{
							u32 crcres = check_crc(buf, dsize);
							if (crcres) {
								printf("Key found: %08X\n", sn);
								free(buf);
								return sn;
							}
							else
								printf("Possible key %08X\n", sn);
						}
						time_t newt;
						time(&newt);
						if (difftime(newt, t) >= 10.) {
							printf("checking %02d%% kps %d\n", (k * 100) / (PRIME_IDX1_LEN*PRIME_IDX2_LEN * 3 * 2), (k - kk) / 10);
							t = newt;
							kk = k;
						}
						k++;
					}
				}
			}
		}
	}
	free(buf);
	return 0xffffffff;
}

//////////////////////////////// Crypto stuff

static void MixKeys(u32 *key)
{
	for (int i = 1; i < 25; i++) {
		key[i + 1] -= key[i + 32];
	}
	for (int i = 25; i < 56; i++) {
		key[i + 1] -= key[i - 23];
	}
	return;
}

static u32 GetNextKey(u32 *key)
{
	u32 posn = *key;
	*key = posn + 1;
	if (55 < (int)(posn + 1)) {
		for (int i = 1; i < 25; i++) {
			key[i + 1] -=key[i + 32];
		}
		for (int i = 25; i < 56; i++) {
			key[i + 1] -=key[i - 23];
		}
		*key = 1;
	}
	return key[*key + 1];
}

static void GenerateKeys(u32 *key, u32 seed)
{
	u32 new_seed = 1;
	key[57] = seed;
	key[56] = seed;
	for (int i = 1; i < 55; i++) {
		int idx = (i * 21) % 55;
		key[idx + 1] = new_seed;
		new_seed = seed - new_seed;
		seed = key[idx + 1];
	}
	MixKeys(key);
	MixKeys(key);
	MixKeys(key);
	MixKeys(key);
	*key = 55;
	return;
}

static void CreateShuffleTables(u32 *data)
{
	for (int i = 0; i < 0x100; i++) {
		shuffle_encrypt[i] = (u8)i;
	}
	for (int i = 0xff; -1 < i; i--) {
		u32 posn = *data;
		*data = posn + 1;
		if (55 < (int)(posn + 1)) {
			MixKeys(data);
			*data = 1;
		}
		u32 new_idx = ((data[*data + 1] >> 16) * (i + 1)) >> 16;
		u8 idx = shuffle_encrypt[new_idx];
		shuffle_encrypt[new_idx] = shuffle_encrypt[i];
		shuffle_encrypt[i] = idx;
		shuffle_decrypt[idx] = (u8)i;
	}
	return;
}

static void Decrypt_Shuffle(u8 *from, u8 *to, int len)
{
	memcpy(to, from, len);
	for (int i = 0; i < (len / 0x100); i++) {
		for (int j = 0; j < 0x100; j++) {
			to[i * 0x100 + shuffle_decrypt[j]] = from[i * 0x100 + j];
		}
	}
	return;
}

static void Encrypt_Shuffle(u8 *from, u8 *to, int len)
{
	memcpy(to, from, len);
	for (int i = 0; i < (len / 0x100); i++) {
		for (int j = 0; j < 0x100; j++) {
			to[i * 0x100 + shuffle_encrypt[j]] = from[i * 0x100 + j];
		}
	}
	return;
}

static void Crypt_Subtract(u32 *key, u32 *data, int len)
{
	int nlen = (len + 3) / 4;
	for (int i = 0; i < nlen; i++) {
		u32 posn = *key;
		*key = posn + 1;
		if (55 < (int)(posn + 1)) {
			MixKeys(key);
			*key = 1;
		}
		data[i] = key[*key + 1] - data[i];
	}
	return;
}

static void Crypt_Xor(u32 *key, u32 *data, int len)
{
	int nlen = (len + 3) / 4;
	for (int i = 0; i < nlen; i++) {
		u32 posn = *key;
		*key = posn + 1;
		if (55 < (int)(posn + 1)) {
			MixKeys(key);
			*key = 1;
		}
		data[i] = key[*key + 1] ^ data[i];
	}
	return;
}

void pso_encrypt(u8* dst, u8* data, u32 length, u32 key)
{
	u32 gameSN[2];
	gameSN[0] = gameSN[1] = key;

	u8 *buf = malloc(length);
	memcpy(buf, data, length);

	GenerateKeys(keys, *(u32*)&buf[length - 4]);
	Crypt_Xor(keys, (u32*)buf, length - 4);
	GenerateKeys(keys, gameSN[0]);
	Crypt_Subtract(keys, (u32*)buf, length);
	GenerateKeys(keys, gameSN[1]);
	CreateShuffleTables(keys);
	Encrypt_Shuffle(buf, dst, length);
	free(buf);
}

void pso_decrypt(u8*dst, u8* data, u32 length, u32 key)
{
	u32 gameSN[2];
	gameSN[0] = gameSN[1] = key;

	GenerateKeys(keys, gameSN[1]);
	CreateShuffleTables(keys);
	Decrypt_Shuffle(data, dst, length);
	GenerateKeys(keys, gameSN[0]);
	Crypt_Subtract(keys, (u32*)dst, length);
	GenerateKeys(keys, *(u32*)&dst[length - 4]);
	Crypt_Xor(keys, (u32*)dst, length - 4);
}

/////////////////////////////////////////

int main(int argc, char **argv)
{
  FILE *fd;
  char msg[512];
  int filenum;

  if(argc < 2) {
    fprintf(stderr, "Usage:\n%s <d|e> <infile> [outfile] [key]\n%s <k> [key]\n", argv[0], argv[0]);
    exit(1);
  }

  crc32_init();

  if (argv[1][0] == 'k') {
	  if (argc > 2) {
		  u32 key = 0;
		  sscanf(argv[2], "%x", &key);
		  printf("Checking SN# %08X\n", key);
		  prime_gen();
		  check_sn(key);
	  }
	  else
	  {
		  prime_gen();
		  gen_sn();
	  }
	  return 0;
  }

  sprintf(msg, "Open %s", argv[2]);
  fd = fopen(argv[2], "rb");
  if(fd==0) {
    perror(msg);
    exit(2);
  }

  fseek(fd, 0, SEEK_END);
  size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  data = (u8*)malloc(size);
  fread(data, 1, size, fd);
  fclose(fd);

  if (*(u32*)data != 0x2f4f5350 && *(u32*)data != 0x564f5350) {
	  printf("%s is not PSO VMS file! aborting", argv[2]);
	  free(data);
	  exit(2);
  }

  if (argv[1][0] == 'e') {
	  printf("Encode start...\n");
	  if (argc < 5) {
		  printf("Encode error: too few arguments!\n");
		  exit(2);
	  }
	  u32 key;
	  sscanf(argv[4], "%x", &key);

	  u8 *dptr = &data[0x200 * *(u16*)&data[0x40] + 0x80];
	  u32 dsize = guess_size(dptr, *(u32*)&data[0x48]);
	  u8 *buf = malloc(dsize);

	  make_crc(dptr, dsize); // in the case if data was edited
	  pso_encrypt(buf, dptr, dsize, key);

	  memcpy(dptr, buf, dsize);
	  fix_vmu_crc(data);

	  sprintf(msg, "Open %s", argv[3]);
	  fd = fopen(argv[3], "wb");
	  if (fd == 0) {
		  perror(msg);
		  exit(2);
	  }
	  fseek(fd, 0, SEEK_SET);
	  fwrite(data, 1, size, fd);
	  fclose(fd);
	  free(buf);
	  printf("Encode done!\n");
	}
  else if (argv[1][0] == 'd') {
	  u32 key = 0xffffffff;
	  if (argc < 5) {
		  printf("No key provided, start brute...\n");
		  prime_gen();
		  u8 *dptr = &data[0x200 * *(u16*)&data[0x40] + 0x80];
		  u32 dsize = guess_size(dptr, *(u32*)&data[0x48]);

		  key = brute(dptr, dsize);

		  if (key == 0xffffffff) {
			  printf("Key not found!\n");
			  exit(2);
		  }
		  printf("brute done!\n");
	  }
	  else {
		  sscanf(argv[4], "%x", &key);
	  }

	  if (argc > 3) {
		  printf("Decode start...\n");
		  u8 *dptr = &data[0x200 * *(u16*)&data[0x40] + 0x80];
		  u32 dsize = guess_size(dptr, *(u32*)&data[0x48]);
		  u8 *buf = malloc(dsize);

		  pso_decrypt(buf, dptr, dsize, key);

		  u32 crcres = check_crc(buf, dsize);
		  if (crcres)
			  printf("CRC check: OK!\n");
		  else
			  printf("CRC check: BAD!!!\n");

		  memcpy(dptr, buf, dsize);
		  fix_vmu_crc(data);

		  sprintf(msg, "Open %s", argv[3]);
		  fd = fopen(argv[3], "wb");
		  if (fd == 0) {
			  perror(msg);
			  exit(2);
		  }
		  fseek(fd, 0, SEEK_SET);
		  fwrite(data, 1, size, fd);
		  fclose(fd);
		  printf("Decode done!\n");
		  free(buf);
	  }
  }

  free(data);
  return 0;
}
