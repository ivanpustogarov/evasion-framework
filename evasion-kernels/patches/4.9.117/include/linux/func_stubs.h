/* func_stubs.h */
#ifndef _LINUX_FUNCSTUBS_H
#define _LINUX_FUNCSTUBS_H

//#include <crypto/hash.h>


/* MD5 **************************************/
/* ivanp: Linux's md5 segfaults, don't have time to debug */

/* https://openwall.info/wiki/people/solar/software/public-domain-source-code/md5 */
/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;

void MD5_Init(MD5_CTX *ctx);
void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size);
void MD5_Final(unsigned char *result, MD5_CTX *ctx);
/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

/*
 * The MD5 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);

/*
 * SET reads 4 input bytes in little-endian byte order and stores them in a
 * properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned memory
 * accesses is just an optimization.  Nothing will break if it fails to detect
 * a suitable architecture.
 *
 * Unfortunately, this optimization may be a C strict aliasing rules violation
 * if the caller's data buffer has effective type that cannot be aliased by
 * MD5_u32plus.  In practice, this problem may occur if these MD5 routines are
 * inlined into a calling function, or with future and dangerously advanced
 * link-time optimizations.  For the time being, keeping these MD5 routines in
 * their own translation unit avoids the problem.
 */
#define SET(n) \
	(ctx->block[(n)] = \
	(MD5_u32plus)ptr[(n) * 4] | \
	((MD5_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((MD5_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((MD5_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(ctx->block[(n)])

/*
 * This processes one or more 64-byte data blocks, but does NOT update the bit
 * counters.  There are no alignment requirements.
 */
static const void *body(MD5_CTX *ctx, const void *data, unsigned long size)
{
	const unsigned char *ptr;
	MD5_u32plus a, b, c, d;
	MD5_u32plus saved_a, saved_b, saved_c, saved_d;

	ptr = (const unsigned char *)data;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;

/* Round 1 */
		STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
		STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
		STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
		STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
		STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
		STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
		STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
		STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
		STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
		STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
		STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
		STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
		STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
		STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
		STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
		STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

/* Round 2 */
		STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
		STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
		STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
		STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
		STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
		STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
		STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
		STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
		STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
		STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
		STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
		STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
		STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
		STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
		STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
		STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

/* Round 3 */
		STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
		STEP(H2, d, a, b, c, GET(8), 0x8771f681, 11)
		STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
		STEP(H2, b, c, d, a, GET(14), 0xfde5380c, 23)
		STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
		STEP(H2, d, a, b, c, GET(4), 0x4bdecfa9, 11)
		STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
		STEP(H2, b, c, d, a, GET(10), 0xbebfbc70, 23)
		STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
		STEP(H2, d, a, b, c, GET(0), 0xeaa127fa, 11)
		STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
		STEP(H2, b, c, d, a, GET(6), 0x04881d05, 23)
		STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
		STEP(H2, d, a, b, c, GET(12), 0xe6db99e5, 11)
		STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
		STEP(H2, b, c, d, a, GET(2), 0xc4ac5665, 23)

/* Round 4 */
		STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
		STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
		STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
		STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
		STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
		STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
		STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
		STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
		STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
		STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
		STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
		STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
		STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
		STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
		STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
		STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;

		ptr += 64;
	} while (size -= 64);

	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;

	return ptr;
}

void MD5_Init(MD5_CTX *ctx)
{
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;
}

void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size)
{
	MD5_u32plus saved_lo;
	unsigned long used, available;

	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		available = 64 - used;

		if (size < available) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, available);
		data = (const unsigned char *)data + available;
		size -= available;
		body(ctx, ctx->buffer, 64);
	}

	if (size >= 64) {
		data = body(ctx, data, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}

	memcpy(ctx->buffer, data, size);
}

#define OUT(dst, src) \
	(dst)[0] = (unsigned char)(src); \
	(dst)[1] = (unsigned char)((src) >> 8); \
	(dst)[2] = (unsigned char)((src) >> 16); \
	(dst)[3] = (unsigned char)((src) >> 24);

void MD5_Final(unsigned char *result, MD5_CTX *ctx)
{
	unsigned long used, available;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80;

	available = 64 - used;

	if (available < 8) {
		memset(&ctx->buffer[used], 0, available);
		body(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}

	memset(&ctx->buffer[used], 0, available - 8);

	ctx->lo <<= 3;
	OUT(&ctx->buffer[56], ctx->lo)
	OUT(&ctx->buffer[60], ctx->hi)

	body(ctx, ctx->buffer, 64);

	OUT(&result[0], ctx->a)
	OUT(&result[4], ctx->b)
	OUT(&result[8], ctx->c)
	OUT(&result[12], ctx->d)

	memset(ctx, 0, sizeof(*ctx));
}



/* MD5 **************************************/



#define SUBPTRS_NUM 16

void* get_valid_pointer(void);
void* generic_stub_p(void);
int   generic_stub_0(unsigned long varg0, ...);
int   generic_stub_1(void);

struct generic_mem_placeholder
{
  void *subptr[SUBPTRS_NUM];
};

/*
* encoded size: 1 byte; 
* Arg type Encoding is done as follows: 
* two highest bits are set: 
* 00 -- not a pointer; 0x00 in hex
* 01 -- pointer (single '*');  0x40 in hex
* 11 -- pointer to pointer; 0xc0
* 10 -- reserved; 0x80
* Lowest 6 bits encode the type as follows:
* 0 - int/uint32_t/u32/unsigned int
* 1 - long/long int/unsigned long int
* 2 - short/unsigned short
* 3 - char/u8/uint8_t/unsigned char
* 4 - struct 
* 5 - void
* 15 - everything else (i.e. custom type,e.g. wait_queue_t)
*/

#define ARG_IS_SINGLE_POINTER(atype) (((atype) >> 6) == 1)
#define ARG_IS_DOUBLE_POINTER(atype) (((atype) >> 6) == 3)
#define ARG_IS_NOT_POINTER(atype) (((atype) >> 6) == 0)
#define ARG_IS_INT(atype) (((atype) & 0x3f) == 0)
#define ARG_IS_LONG(atype) (((atype) & 0x3f) == 1)
#define ARG_IS_SHORT(atype) (((atype) & 0x3f) == 2)
#define ARG_IS_CHAR(atype) (((atype) & 0x3f) == 3)
#define ARG_IS_STRUCT(atype) (((atype) & 0x3f) == 4)
#define ARG_IS_VOID(atype) (((atype) & 0x3f) == 5)
#define ARG_IS_CONST(atype) (((atype) & 0x20))

typedef enum {
  RETTYPE_NOTPOINTER=0,
  RETTYPE_POINTER=1
} rettype_t;


typedef struct {
  rettype_t rettype; /* 0 - not a pointer; 1 - pointer */
  unsigned char num_args;
  unsigned char arg_types[10];
} func_proto_t;

/* https://stackoverflow.com/questions/11126027/using-md5-in-kernel-space-of-linux?rq=1 */
//int md5_hash(char *result, char* data, size_t len){
//    struct shash_desc *desc;
//    desc = kmalloc(sizeof(*desc), GFP_KERNEL);
//    desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
//
//    if(desc->tfm == NULL)
//        return -1;
//
//    crypto_shash_init(desc);
//    crypto_shash_update(desc, data, len);
//    crypto_shash_final(desc, result);
//    crypto_free_shash(desc->tfm);
//
//    return 0;
//}


uint32_t ugly_hash(char *str, int len)
{
  
  MD5_CTX ctx;
  char md5[20];
  uint32_t ret = 0; /* first 4 bytes of md5 as integer */

  MD5_Init(&ctx);
  MD5_Update(&ctx, str, len);
  MD5_Final(md5, &ctx);
  
  ret = *(uint32_t *)md5; // will take the fist 4 bytes, that's what we need
  return ret;

  //unsigned int hash = 0;
  //int i = 0;
  //for (i = 0; i<len; i++)
  //   hash = hash*33 + str[i];
  //   //hash = ( hash + (324723947 + str[i])) ^ 0xc1bd59f1;
  //return hash;
}

/* record format:
   [FUNC_NAME_HASH 4B] [RET TYPE 1B] [NUM_ARGS 1B] [ARG_TYPE 1B] ...
*/
int get_func_sig(char *name, void *protos, func_proto_t *proto)
{
  int i,j = 0;
  unsigned char num_args;
  unsigned char N;
  unsigned int h = 0;
  unsigned char *p;
  uint32_t hash = ugly_hash(name, strlen(name));

  N = *(unsigned char *)protos; /* Total number of function prototypes */
  p = (unsigned char *)protos;
  p++;

  //printk("%s(): have information about %hhu functions\n", __func__, *(unsigned char *)protos);

  for(i = 0; i<N; i++)
  {
    h = *(uint32_t *)p; /* md5 hash of the function name */
    if (h == hash)
    {
      //printk("%s(): found hash 0x%x (for name %s), i = %d\n", __func__, hash, name, i);
      p = p+4; /* now p points to func ret type (0 -- not a pointer, 1 -- pointer) */
      proto->rettype = *(unsigned char *)p;

      p = p+1;
      num_args = *p;
      proto->num_args = num_args;

      //printk("           num_arge=%hhd\n", num_args);
      p = p + 1;
      for(j=0;j<num_args;j++)
      {
        proto->arg_types[j] = *(unsigned char *)p;
        //printk("           arg%d_type=0x%hhx\n", j, proto->arg_types[j]);
        p = p + 1;
      }
      return 1;
    }
    p = p+4; /* jump over func name hash */
    p = p+1; /* jump over ret type */
    num_args = *p;
    p = p + 1 + num_args;
  }
  //printk("%s(): func '%s' -> 0x%x\n", __func__, name, hash);
  return 0;
}


void* get_valid_pointer(void)
{
  int i = 0;
  struct generic_mem_placeholder *gmp;
  gmp = kzalloc(sizeof(struct generic_mem_placeholder), GFP_KERNEL);
  if(!gmp)
    printk("get_valid_pointer(): kzalloc failed (not enough mem?)\n");
  for(i=0;i<SUBPTRS_NUM;i++)
  {
    gmp->subptr[i] = kzalloc(16, GFP_KERNEL);
    if(!gmp->subptr[i])
      printk("get_valid_pointer(): kzalloc failed for subpointer (not enough mem?)\n");
  }
  //printk("generic_stub_p() saved the day with pointer 0x%p\n",gmp);
  return (void *)gmp;
}

void* generic_stub_p(void)
{
  printk("generic_stub_p() saved the day\n");
  return get_valid_pointer();
}

#define HASH_SIZE 4
char *find_reloc(char *deadbeef, uint32_t target_md5)
{
  int i = 0;
  uint32_t entry_md5 = 0;
  uint8_t fname_len = 0;
  char *p = deadbeef;

  uint16_t n_entries = *(uint16_t *)p;
  p = p+2;
  //printk("%s(): Number of entires = %hu\n", __func__, n_entries);
  for(i=0;i<n_entries;i++)
  {
    entry_md5 =  *(uint32_t *)p;
    if(entry_md5 == target_md5)
      return p+4;
    p = p+4;
    fname_len = *(uint8_t *)p;
    p = p+1+fname_len;
  }
  return NULL;
}

typedef char* (*fptr)(void);
// Notes on %pS and __builtin_return_address: https://www.kernel.org/doc/Documentation/printk-formats.txt
int generic_stub_0(unsigned long varg0, ...)
{
  //printk("generic_stub_0() was called from 0x%08X \n",__return_address());
  char buf[256];
  char md5[20];
  char *sp; // To replace space with '\0' in 'qseecom_probe+0x123\0x555 [qseecom]'; we don't need module's name
  unsigned long get_relocs_deadbeef_addr = 0;
  unsigned long get_func_protos_addr = 0;
  fptr get_deadbeef;
  fptr get_func_protos;
  MD5_CTX ctx;
  char *deadbeef;
  char *protos;
  char *reloc;
  uint32_t target_md5 = 0;
  uint8_t fname_len = 0;
  char fname[256];
  func_proto_t proto;
  int i = 0;
  unsigned char atype;
  unsigned char atype_next;
  unsigned long args_copy[16];

  va_list vargs;
  va_start(vargs, varg0);

//  printk("%s: called from %pS\n", __func__,
//				(void *)__builtin_return_address(0));
  sprintf(buf, "%pS",(void *)__builtin_return_address(0)-4);
  sp = strchr(buf, ' ');
  *sp=0;
  printk("%s: called from %s\n", __func__, buf);

  MD5_Init(&ctx);
  MD5_Update(&ctx, buf, strlen(buf));
  MD5_Final(md5, &ctx);

  //printk("%s: md5: %*phN\n", __func__, 16, md5);

  /* Get relocation info */
  get_relocs_deadbeef_addr = kallsyms_lookup_name("get_relocs_deadbeef");

  if(!get_relocs_deadbeef_addr)
  {
    printk("%s(): Could not find relocs (did you link you module with inject.c?), will not mess with args, just returning 0\n", __func__);
    return 0;
  }

  get_deadbeef = (fptr) get_relocs_deadbeef_addr;
  deadbeef = get_deadbeef();
  target_md5 = *(uint32_t *)md5; // will take the fist 4 bytes, that's what we need

  /* Should get us to the funcname length position */
  reloc=find_reloc(deadbeef, target_md5);
  if(!reloc)
  {
    printk("%s(): did not find reloc, returning 0\n", __func__); 
    return 0;
  }

  fname_len = *(uint8_t *)reloc;
  strncpy(fname, reloc+1, fname_len);
  fname[fname_len] = '\0';
  printk("%s(): orignal function name: %s()\n", __func__, fname); 
 
 
  /* Now get function prototype for the original function */
  get_func_protos_addr = kallsyms_lookup_name("get_func_protos");
  if(!get_func_protos_addr)
  {
    printk("%s(): Could not find func prototypes (did you link you module with inject.c?), will not mess with args, just returning 0\n", __func__);
    return 0;
  }
  get_func_protos = (fptr) get_func_protos_addr;
  protos = get_func_protos();
  //printk("%s(): protos = %hhx %hhx %hhx\n", __func__, protos[0], protos[1], protos[2]);
  get_func_sig(fname, protos, &proto);


#if 1
  /* If an arg is a pointer that points to zero, and the next arg is an integer
     of either size 4(int) or 1(char), we conjecture that the function puts
     a small number to that location */
  if(proto.num_args <= 6 ) /* don't mess up with args which are not in registers */
  {
    for(i=0;i<proto.num_args;i++)
    {
      if(i==0)
        args_copy[i] = varg0;
      else
      {
        unsigned long varg = va_arg(vargs, int);
        args_copy[i] = varg;
      }
    }

    printk("         Looking for out buffers\n"); 
    for(i=0;i<proto.num_args;i++)
    {
      atype = proto.arg_types[i];
      if(i+1<proto.num_args)
      {

        atype_next = proto.arg_types[i+1];

        //printk("\n                 arg[i]=0x%lx, arg[i+1]=0x%lx\n", args_copy[i], args_copy[i+1]);
        //printk("                 ARG_IS_SINGLE_POINTER(atype)=%s\n", ARG_IS_SINGLE_POINTER(atype) ? "true" : "false");
        //printk("                 ARG_IS_VOID(atype)=%s\n", ARG_IS_VOID(atype) ? "true" : "false");
        //printk("                 !ARG_IS_CONST(atype)=%s\n", !ARG_IS_CONST(atype) ? "true" : "false");
        //printk("                 (ARG_IS_INT(atype_next) || ARG_IS_LONG(atype_next))=%s\n", (ARG_IS_INT(atype_next) || ARG_IS_LONG(atype_next)) ? "true" : "false");
        //printk("                 ARG_IS_NOT__POINTER(atype_next)=%s\n", ARG_IS_NOT_POINTER(atype_next) ? "true" : "false");
	//if((args_copy[i] != 0) && ARG_IS_SINGLE_POINTER(atype))
        //  printk("                 *(uint32_t *)(args_copy[i])=%lx\n", *(uint32_t *)(args_copy[i]));

        if( ARG_IS_SINGLE_POINTER(atype) && 
	    (ARG_IS_INT(atype) ||  ARG_IS_LONG(atype)) && 
	    (args_copy[i]!=0))
        {
          uint32_t *addr = (uint32_t *)(args_copy[i]);
          *addr = 42; /* Some small number */
          printk("         replaced arg%d with 42)\n", i); 
        }

        if( ARG_IS_SINGLE_POINTER(atype) &&  /*                 */
            ARG_IS_VOID(atype) &&            /* arg is (void *) */ 
            !ARG_IS_CONST(atype) &&          /*                 */
            ( (ARG_IS_INT(atype_next) || ARG_IS_LONG(atype_next)) && ARG_IS_NOT_POINTER(atype_next) ) && /* Next arg is int/long/size_t */

            (args_copy[i] != 0)  &&

            (
              ((args_copy[i+1] == 4) && (*(uint32_t *)(args_copy[i]) == 0)) || /* The next arg seems to be sizeof(int)) or sizeof(char) => the previous param is a out buffer */
              //((args_copy[i+1] == 4) ) || /* The next arg seems to be sizeof(int)) or sizeof(char) => the previous param is a out buffer */
              ((args_copy[i+1] == 1) && (*(uint8_t  *)(args_copy[i]) == 0)) /* The next arg seems to be sizeof(int)) or sizeof(char) => the previous param is a out buffer */
	    ) )
            //((args_copy[i+1] == 4) || (args_copy[i+1] == 1)) && /* The next arg seems to be sizeof(int)) or sizeof(char) => the previous param is a out buffer */
            //((args_copy[i] != 0) && (*(uint32_t *)(args_copy[i]) == 0)) ) /* out buffers are usually zeroed out */
        {
          uint32_t *addr = (uint32_t *)(args_copy[i]);
          *addr = 42; /* Some small number */
          printk("         replaced arg%d with 42)\n", i); 
        }

      }
    }
  }
#endif

#if 0
  /* First arg */
  printk("%s(): num of args = %d\n", __func__, proto.num_args);
  if(proto.num_args >= 1)
  {
    atype = proto.arg_types[0];

    printk("%s(): varg0 atype=0x%hhx \n", __func__, atype);
    if( ARG_IS_SINGLE_POINTER(atype) && (ARG_IS_INT(atype) ||  ARG_IS_LONG(atype)) )
    {
      printk("%s(): varg0 type: pointer to int; varg0=%lu \n", __func__, varg0);
    } else if(ARG_IS_DOUBLE_POINTER(atype))
    {
      printk("%s(): varg0 type: double pointer; varg0=0x%lx \n", __func__, varg0);
    } else if(ARG_IS_NOT_POINTER(atype) && (ARG_IS_INT(atype) ||  ARG_IS_LONG(atype)) )
    {
      printk("%s(): varg0 type: simple int/long; varg0=0x%lx \n", __func__, varg0);
    } else if(ARG_IS_NOT_POINTER(atype) && !ARG_IS_INT(atype) &&  !ARG_IS_LONG(atype) )
    {
      printk("%s(): varg0 type: simple int/long; varg0=0x%lx \n", __func__, varg0);
    } else if(ARG_IS_NOT_POINTER(atype) && ARG_IS_STRUCT(atype))
    {
      printk("%s(): varg0 type: struct; varg0=0x%lx \n", __func__, varg0);
    } else if(ARG_IS_SINGLE_POINTER(atype) && ARG_IS_STRUCT(atype))
    {
      printk("%s(): varg0 type: pointer to struct; varg0=0x%lx \n", __func__, varg0);
    } else
    {
      printk("%s(): varg0 type is complex; varg0=0x%lx \n", __func__, varg0);
    }
  }

  /* All other args */
  for(i=1;i<proto.num_args;i++)
  {
    atype = proto.arg_types[i];
    if( ARG_IS_SINGLE_POINTER(atype) && (ARG_IS_INT(atype) ||  ARG_IS_LONG(atype)) )
    {
      unsigned int varg = va_arg(vargs, int);
      printk("%s(): arg %d is a pointer to int\n", __func__, i);
      printk("%s(): arg %d is %u\n", __func__, i, varg);
    } else if(ARG_IS_DOUBLE_POINTER(atype))
    {
      void *varg = va_arg(vargs, void *);
      printk("%s(): arg %d is a double pointer\n", __func__, i);
      printk("%s(): arg %d is %p\n", __func__, i, varg);
    } else
    {
      unsigned long varg = va_arg(vargs, unsigned long);
    }
    //else
    //  printk("%s(): arg %d is %lu\n", __func__, i, varg0);
  }

  va_end(vargs);
#endif
  
  //printk("%s: deadbeef: %hhu %hhu %hhu\n", __func__, deadbeef[0], deadbeef[1], deadbeef[2]);

  return 0;
}

int generic_stub_1()
{
  printk("generic_stub_1() saved the day\n");
  return 1;
}

#endif
