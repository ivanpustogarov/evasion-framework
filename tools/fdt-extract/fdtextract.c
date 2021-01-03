#include <stdlib.h>
#include <time.h>  
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <copyfile.h>
#else
#include <sys/sendfile.h>
#endif

#include "libfdt.h"
#include "util.h"

#define streq(a, b)	(strcmp((a), (b)) == 0)
#define streqn(a, b, n)	(strncmp((a), (b), (n)) == 0)
#define strnoteq(a, b)	(strcmp((a), (b)) != 0)

#define OUTNAME "temp.dtb"
//#define OUTNAME_PACKED "temp-packed.dtb"
#define DTB_ALIEN "vexpress-v2p-ca9-kernel4.9.117.dtb"
//#define DTB_HOST "msm8610-cdp.dtb" /* Contains "qcom,csid" */
//#define DTB_HOST "msm8974-v1-sim.dtb"/* Contains "qcom,msm-hsuart-v14" */
//#define DTB_HOST "msm8610-cdp.dtb" /* Contains "qcom,actuator" */
#define DTB_MT6765 "mt6765.dtb" /* Contains mediatek,imgsys */

#define COMPATIBLE_HSUART "qcom,msm-hsuart-v14"
#define COMPATIBLE_CSID "qcom,csid"
#define COMPATIBLE_MSMCAM "qcom,msm-cam"
#define COMPATIBLE_MSMACTUATOR "qcom,actuator"
#define COMPATIBLE_GIC "arm,cortex-a9-gic"
#define COMPATIBLE_I2C_VERSATILE "arm,versatile-i2c"
#define COMPATIBLE_MEDIATEK_IMGSYS "mediatek,imgsys"

#define COMPATIBLE COMPATIBLE_MEDIATEK_IMGSYS
#define DTB_HOST DTB_MT6765
#define DEBUG

const char status_ok[] = "ok";

int print_hex(const void *p, int len)
{
  unsigned char *c = (unsigned char *)p;
  for (int i = 0; i < len; i++)
  {
    printf("%02hhx ", *c); 
    c++;
  }
  printf("%s","\n");
  return 0;
}

void *load_blob(const char *filename)
{
  char *blob;
  size_t len;
  int ret = utilfdt_read_err(filename, &blob, &len);
  
  if (ret)
  {
    printf("error: couldn't open blob from \"%s\": %s\n", filename, strerror(ret));
    //printf("usage: fdttest DTBFILE\n");
    //exit(1);
    return NULL;
  }
  return blob;
}


void save_blob(const char *filename, void *fdt)
{
	size_t size = fdt_totalsize(fdt);
	void *tmp;
	int ret;

	/* Make a temp copy of the blob so that valgrind won't check
	 * about uninitialized bits in the pieces between blocks */
	tmp = xmalloc(size);
	fdt_move(fdt, tmp, size);
	//VALGRIND_MAKE_MEM_DEFINED(tmp, size);
	ret = utilfdt_write_err(filename, tmp);
	if (ret)
		printf("Couldn't write blob to \"%s\": %s", filename,
		       strerror(ret));
	free(tmp);
}

int OSCopyFile(const char* source, const char* destination)
{    
    int input, output;    
    if ((input = open(source, O_RDONLY)) == -1)
    {
        return -1;
    }    
    if ((output = creat(destination, 0660)) == -1)
    {
        close(input);
        return -1;
    }

    //Here we use kernel-space copying for performance reasons
#if defined(__APPLE__) || defined(__FreeBSD__)
    //fcopyfile works on FreeBSD and OS X 10.5+ 
    int result = fcopyfile(input, output, 0, COPYFILE_ALL);
#else
    //sendfile will work with non-socket output (i.e. regular file) on Linux 2.6.33+
    off_t bytesCopied = 0;
    struct stat fileinfo = {0};
    fstat(input, &fileinfo);
    int result = sendfile(output, input, &bytesCopied, fileinfo.st_size);
#endif

    close(input);
    close(output);

    return result;
}

#if 0
/* Check if a value of a property is a phandle of another node
 * 
 *  return:
 *   1 if value is a phandle
 *   0 if not 
 */
int prop_value_is_phandle(void *fdt, const void *value, int lenp)
{
  if(lenp != 4) /* phandles are u32 */
    return 0;
  uint32_t phandle = fdt32_to_cpu(*((uint32_t *) value));
  //printf("%s(): phandle = %x\n", __func__, phandle);
  int n = fdt_node_offset_by_phandle(fdt, phandle);
  if(n<0)
    return 0;
  return 1;
}
#endif

uint32_t get_interrupt_cells_for_node(void *fdt, int node)
{
  //int prop_offset, prop_len;
  //const char *prop_name;

  const void *valuep;
  int lenp; 
  int nnamelen = 0; /* A temp variable, reused for all nodes */
  const char *nname = NULL; /* A temp variable, reused for all nodes */

  /* Look for interrupt-cells inside the node */
  //printf(" - getting interrupt cells\n"); 
  valuep = fdt_getprop(fdt, node, "#interrupt-cells", &lenp); 
  if(valuep) 
  {
    assert(lenp == 4); /* Should be of uint32_t */
    nname = fdt_get_name(fdt, node, &nnamelen);
    printf("    Found #interrupt-cells in node %s\n", nname);
    return fdt32_to_cpu(*(uint32_t *)valuep);  
  }
  
  /* Let's look for interrupt-parent */
  uint32_t intcparent = 0;
  valuep = fdt_getprop(fdt, node, "interrupt-parent", &lenp); 
  if(valuep) 
  {
    assert(lenp == 4); /* phandler should be uint32_t */
    //printf(" - we have interrupt-parent\n"); 
    intcparent = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*(uint32_t *)valuep));
    nname = fdt_get_name(fdt, intcparent, &nnamelen);
    //printf(" - searching in interrupt parent '%s' (offset=%d)\n", nname, intcparent); 
    //getc(stdin);
    return get_interrupt_cells_for_node(fdt, intcparent);
  }

  /* If no interrupt-parent, then let's search parent nodes up to root (root offset is 0) */
  int parent = fdt_parent_offset(fdt, node);
  if(parent == -1)
    return 0;
  nname = fdt_get_name(fdt, parent, &nnamelen);
  //printf(" - searching in parent '%s', offset=%d\n", nname, parent); 
  //getc(stdin);
  return get_interrupt_cells_for_node(fdt, parent);
}

uint32_t get_address_cells_for_node(void *fdt, int node)
{
  //int prop_offset, prop_len;
  //const char *prop_name;

  const void *valuep;
  int lenp; 
  int nnamelen = 0; /* A temp variable, reused for all nodes */
  const char *nname = NULL; /* A temp variable, reused for all nodes */

  /* Look for interrupt-cells inside the node */
  //printf(" - getting interrupt cells\n"); 
  valuep = fdt_getprop(fdt, node, "#address-cells", &lenp); 
  if(valuep) 
  {
    assert(lenp == 4); /* Should be of uint32_t */
    nname = fdt_get_name(fdt, node, &nnamelen);
    printf(" + Found #address-cells in node %s\n", nname);
    return fdt32_to_cpu(*(uint32_t *)valuep);  
  }
  
  /* Search parent nodes up to root */
  int parent = fdt_parent_offset(fdt, node);
  nname = fdt_get_name(fdt, parent, &nnamelen);
  //printf(" - searching in parent '%s'\n", nname); 
  //getc(stdin);
  return get_address_cells_for_node(fdt, parent);
}


/* Generate an array containing interrupt number for gic interrupt controller:
   'interrupts = <0 50 4>,  <0 51 4>;' */
#define GIC_START_INT 50
void *generate_gic_interrupt_values(int count)
{
  uint32_t i = GIC_START_INT;
  uint32_t *new_value = malloc(count*3*sizeof(uint32_t)); /* every interrupt specifier is 3 bytes for <gic> */
  uint32_t *p = new_value;
  for(i=GIC_START_INT; i<GIC_START_INT+count; i++)
  {
    *p     = cpu_to_fdt32(0);
    *(p+1) = cpu_to_fdt32(i);
    *(p+2) = cpu_to_fdt32(4);
    p = p + 3;
  }
  return new_value;
}

/* Generate an array containing reg values:
   'reg = <0 0x2b000000 0 0x1000>;' */
#define REG_START 0x4ba00000
void *generate_reg_value()
{
  uint32_t *new_value = malloc(4*sizeof(uint32_t)); /* every reg values is 4 ints */
  uint32_t *p = new_value;

  *p     = cpu_to_fdt32(0);
  *(p+1) = cpu_to_fdt32(REG_START);
  *(p+2) = cpu_to_fdt32(0);
  *(p+3) = cpu_to_fdt32(0x1000);

  return new_value;
}

/* Generate an i2c reg value
   'reg = <0x4a>;' */
#define REG_START_I2C 0x4a
void *generate_reg_value_i2c()
{
  uint32_t *new_value = malloc(sizeof(uint32_t));
  *new_value = cpu_to_fdt32(0x4a);
  return new_value;
}

/* Find a prent node in fdt_dst for node in fdt_src that we want to copy */
int find_new_parent(void *fdt_dst, void *fdt_src, int src_node_offset)
{
  //int prop_offset, prop_len;
  //int prop_len;
  //const void *prop_value;
  int nnamelen = 0; /* A temp variable, reused for all nodes */
  const char *nname = NULL; /* A temp variable, reused for all nodes */
  //const char *prop_name;

#if 0 /* ivanp: before we used the reg field to decide if the node was an i2c device: i2c devices have addresses as 0x6e,
         while memory mapped devices have addreses larger than 0xff (e.g. 0x12345678) */
  prop_value = fdt_getprop(fdt_src, src_node_offset, "reg", &prop_len);
  assert(prop_value);
  /* FIXME: for now we deal with the maximum value of address-cells of 2, this
   * seems reasonable for all the cases I encountered so far, but its better
   * make it more generic */

  uint32_t address_cells = get_address_cells_for_node(fdt_src, src_node_offset);

  uint32_t reg = fdt32_to_cpu(*(uint32_t *)prop_value);
  printf(" - reg = 0x%x\n", reg);
  if(reg > 0xff)
    return 0; /* root node */

  /* Let's confirm that the copied node is a child if i2c */
  printf(" - The node looks like an i2c device\n");
#endif
  int src_parent_offset = fdt_parent_offset(fdt_src, src_node_offset); 
  while(src_parent_offset >= 0)
  {
    nname = fdt_get_name(fdt_src, src_parent_offset, &nnamelen);
    //printf("    - parent = %s\n", nname);
    if(streqn(nname, "i2c", 3))
      break;
    src_parent_offset = fdt_parent_offset(fdt_src, src_parent_offset); 
  }

  /* If we passed beyong root node and did not find i2c node */
  if(src_parent_offset < 0)
  {
    //printf(" - After checking parents nodes, the msm node is not an i2c device, hmmm...\n");
    printf("    After checking the parent: the node is NOT an i2c device.\n");
    return 0;
  }

  /* Seems it's an i2c device, we need to attach it to i2c bus in the evasion kernel */
  int dst_i2c_node_offset = fdt_node_offset_by_compatible(fdt_dst, -1, COMPATIBLE_I2C_VERSATILE);
  //printf(" - parent = %s\n", nname);
  if(dst_i2c_node_offset <=  0) /* Addition to deal with virt board that does not have i2c */
  {
    printf("warning: after checking the parents: the node IS an i2c device, but your current board (virt?) does not have i2c bus entry, so adding the copied node under root! \n");
    return 0;
  }
  assert(dst_i2c_node_offset > 0); /* Should be present in vexrpress dtb */
  nname = fdt_get_name(fdt_dst, dst_i2c_node_offset, &nnamelen);
  printf("    After checking the parents: the node IS an i2c device.\n");
  //printf(" - found i2c in fdt_dst: %s\n", nname);
  return dst_i2c_node_offset;
  //while (src_i2c_node_offset != -FDT_ERR_NOTFOUND) 
  //{
  //  offset = fdt_node_offset_by_compatible(fdt, offset, COMPATIBLE_I2C_VERSATILE);
  //}

  //while(src_parent >= 0)  

  //dst_newnode_offset = fdt_add_subnode(fdt_dst, 0, node_name);
}


/*
   Add something like this to the the device tree
	hdlcd@2b000000 {
		compatible = "arm,hdlcd";
		reg = <0 0x2b000000 0 0x1000>;
		interrupts = <0 85 4>;
	};
*/
void *add_generic_node(void *_fdt_dst, const char *compatible, char *new_node_name)
{
  void *fdt_dst; /* This is a copy of _fdt_dest but with increased size */
  int dst_newsize;
  int dst_newnode_offset;
  const char *nname = NULL; /* A temp variable, used for debug print */
  int nnamelen = 0; /* A temp variable, used for debug print */
  //int prop_offset, prop_len;
  //const void *prop_value;
  //const char *prop_name;
  uint32_t prop_newphandle; /* will be used for newly generated phandle for the copied node */
  int parent = 0; /* parent node under which to add a new node, 0 means root node */

  dst_newsize = 2*fdt_totalsize(_fdt_dst);
  fdt_dst = xmalloc(dst_newsize);
  /* don't leak uninitialized memory into our output */
  memset(fdt_dst, 0, dst_newsize);

  int err = fdt_open_into(_fdt_dst, fdt_dst, dst_newsize);
  if (err)
  {
    printf("fdt_open_into(): %s", fdt_strerror(err));
    free(fdt_dst);
    return NULL;
  }

  /* We have can have a new node either under root or under i2c bus,
     in the latter case you need to append @i2c to the compatibility property,e.g.:
      'mediatek,flashlights_dummy_i2c' becomes 'mediatek,flashlights_dummy_i2c@i2c'
  */
  char *bus_type = strstr(compatible, "@");
  if(bus_type)
  {
    bus_type[0] = '\0'; /* replace '@' with null byte, so that compatible property does not contain bus name */
    bus_type++; /* bus name goes after '@' */
    if(streq(bus_type, "i2c"))
    {
      parent = fdt_node_offset_by_compatible(fdt_dst, -1, COMPATIBLE_I2C_VERSATILE);
      assert(parent > 0); /* Should be present in vexrpress dtb */
      nname = fdt_get_name(fdt_dst, parent, &nnamelen);
      printf(" - parent for new node = %s\n", nname);
    } else
    {
      printf("error: bus type '%s' is not supported\n", bus_type);
      exit(0);
    }
  }

  /* We striiped off '@i2c' part from compatible property, so we check is the node already exists */
  if( fdt_node_offset_by_compatible(fdt_dst, -1, compatible) >= 0 )
  {
    printf("[-] error: the evasion dtb already contains node with compatibility property '%s'\n", compatible);
    exit(0);
  }
  
  void *reg_value = generate_reg_value(); /* TODO: don't gnereate both value, make it dependent on the bus */
  void *reg_value_i2c = generate_reg_value_i2c();
  char *node_name = malloc(256); /* TODO: compute size dynamically */
  if(new_node_name != NULL)
    sprintf(node_name, "%s", new_node_name);
  else
    sprintf(node_name, "%s_%d@%x", "generic_node", rand(), parent ? REG_START_I2C : REG_START);

  printf("[+] Preparing new empty node '%s' under %s in evasion dtb\n", node_name, parent ? "i2c" : "root"); 
  dst_newnode_offset = fdt_add_subnode(fdt_dst, parent, node_name);

  //prop_value = fdt_getprop(fdt_src, src_node_offset, "reg", prop_len);
  //dst_newnode_offset = fdt_add_subnode(fdt_dst, 0, node_name);


  if(dst_newnode_offset < 0)
  {
    printf("[-] Adding new node failed: %s\n", strerror(dst_newnode_offset));
    free(fdt_dst);
    return NULL;
  }

  printf("[+] Adding new fields\n");
  fdt_setprop(fdt_dst, dst_newnode_offset, "compatible", &compatible[0], strlen(compatible)+1); /* we add 1 to the length in order to pass '\0' character */
  if(parent && streq(bus_type, "i2c"))
    fdt_setprop(fdt_dst, dst_newnode_offset, "reg", reg_value_i2c, sizeof(uint32_t));
  else
  {
    fdt_setprop(fdt_dst, dst_newnode_offset, "reg", reg_value, 4*sizeof(uint32_t));
    void *gic_int_values = generate_gic_interrupt_values(1); /* Generate one interrupt entry */
    fdt_setprop(fdt_dst, dst_newnode_offset, "interrupts", gic_int_values, 3*sizeof(uint32_t)); /* gic has #interrupt-cells=3 */
  }
  if(fdt_generate_phandle(fdt_dst, &prop_newphandle) < 0)
  {
    printf("error: could not generate a new phandle for the new node\n");
    exit(-1);
  }
  prop_newphandle = (fdt32_to_cpu(prop_newphandle));
  fdt_setprop(fdt_dst, dst_newnode_offset, "phandle", &prop_newphandle, sizeof(uint32_t));

  /* Now add a dummy empty subnode */
  sprintf(node_name, "%s_%d", "generic_subnode", rand());
  printf("[+] Adding dummy subnode '%s'\n", node_name);
  dst_newnode_offset = fdt_add_subnode(fdt_dst, dst_newnode_offset, node_name);
  //free(node_name);
  return fdt_dst;
}

/* Copy the node in '@fdt_src' at offset '@node_offset' to '@_fdt_dest' 
 * 
 * @node_name: assign this name to the copied node in dst (can be different from the original node name in src)
 *
 * returns:
 *          a pointer a copy of @_fdt_dest containing the new node
 *          We need to copy the fdt in order to increase its size
 *          NULL if there was an error
 */
void *copy_node(void *_fdt_dst, void *fdt_src, int src_node_offset, const char *node_name)
{
  void *fdt_dst; /* This is a copy of _fdt_dest but with increased size */
  int dst_newsize;
  int dst_newnode_offset;
  int prop_offset, prop_len;
  const void *prop_value;
  const char *prop_name;
  uint32_t prop_newphandle; /* will be used for newly generated phandle for the copied node */
#if 0
  int nnamelen = 0; /* A temp variable, reused for all nodes */
  const char *nname = NULL; /* A temp variable, reused for all nodes */
#endif

  dst_newsize = 2*fdt_totalsize(_fdt_dst);
  fdt_dst = xmalloc(dst_newsize);
  /* don't leak uninitialized memory into our output */
  memset(fdt_dst, 0, dst_newsize);

  int err = fdt_open_into(_fdt_dst, fdt_dst, dst_newsize);
  if (err)
  {
    printf("fdt_open_into(): %s", fdt_strerror(err));
    free(fdt_dst);
    return NULL;
  }

#undef GIC_REPLACE
#ifdef GIC_REPLACE
  /* Find <gic> node in the dst device tree (i.e. device tree of the evasion kernel),
     we will replace msm interrupt controller for this one */
  int gic_alien_noffset = fdt_node_offset_by_compatible(fdt_dst, -1, COMPATIBLE_GIC);
  if(gic_alien_noffset<0)
  {
    printf("error: could not find <gic> node in the alient kerenl\n");
    exit(0);
  }
  nname = fdt_get_name(fdt_dst, gic_alien_noffset, &nnamelen);
  printf("Found <gic> node with name '%s'\n", nname);
#endif

  /* Get '#interrupt-cells' property (might be inherited) for the msm node
     we will use it when replacing 'interrupts' property */
  //printf("[+] Getting node's interrupt cells values from the host dtb\n");
  printf("[+] Analyzing node\n");
  uint32_t interrupt_cells = get_interrupt_cells_for_node(fdt_src, src_node_offset);
  if(interrupt_cells == 0)
    printf("[?] warning: could not find interrupt cells (will be a problem if our nodes has 'interrupts' property, but ok otherwise)\n");
  printf("    interrupt cells = %u\n", interrupt_cells);

  /* We create an empty node in the destination fdt and copy each of the node's properties from src
     We either add to under the root node or under i2c controller */
  printf("    Looking for node's parent in host dtb\n");
  int new_parent = find_new_parent(fdt_dst, fdt_src, src_node_offset);
  printf("[+] Preparing new empty node under %s in evasion dtb\n", ((new_parent==0) ? "root" : "i2c")); 
  //nname = fdt_get_name(fdt_dst, new_parent, &nnamelen);
  //printf(" - new parent = %s\n", nname);
  //exit(0);
  dst_newnode_offset = fdt_add_subnode(fdt_dst, new_parent, node_name);

  //prop_value = fdt_getprop(fdt_src, src_node_offset, "reg", prop_len);
  //dst_newnode_offset = fdt_add_subnode(fdt_dst, 0, node_name);


  if(dst_newnode_offset < 0)
  {
    printf("[-] Adding new node failed: %s\n", strerror(dst_newnode_offset));
    free(fdt_dst);
    return NULL;
  }
 

  /* Copy properties from src fdt to dst */
  printf("[+] Copying host node's properties into the prepared empty node\n");
  fdt_for_each_property_offset(prop_offset, fdt_src, src_node_offset) 
  {
    prop_value = fdt_getprop_by_offset(fdt_src, prop_offset, &prop_name, &prop_len);
    if(!prop_value)
    {
      printf("%s(): error (BUG): could not access a property\n", __func__);
      exit(0);
    }
    else
    {
      if(streq(prop_name, "interrupt-parent")) /* Don't copy interrupt-parent, will use root node's interrupt controller, gic, by default */
      {
        printf(" - skipping 'interrupt-parent' property\n");
        continue;
      }
      else if(streq(prop_name, "interrupt-map")) /* No need for interrupt-map since we use just one gic */
      {
        printf(" - skipping 'interrupt-map' property\n");
        continue;
      }
      else if(streq(prop_name, "#interrupt-cells")) /* No need for interrupt-map since we use just one gic */
      {
        printf(" - Skipping '#interrupt-cells' property\n");
        continue;
      }
      else if(streq(prop_name, "status")) /* No need for interrupt-map since we use just one gic */
      {
        printf("    - setting 'status' property to \"ok\"\n");
        fdt_setprop(fdt_dst, dst_newnode_offset, prop_name, &status_ok, sizeof(status_ok));
        continue;
      }
      else if(streq(prop_name, "interrupts")) /* No need for interrupt-map since we use just one gic */
      {
        printf(" - modifying 'interrupts' property\n");
	assert(interrupt_cells != 0);
	printf(" - old values: ");
	print_hex(prop_value, prop_len);
        int int_count = (prop_len/sizeof(uint32_t))/interrupt_cells; /* prop_len is in bytes, but each number is u32, so we divide by 4 */
	printf(" - we have %d interrupt specifiers\n", int_count);
	void *gic_int_values = generate_gic_interrupt_values(int_count);
        fdt_setprop(fdt_dst, dst_newnode_offset, prop_name, gic_int_values, 3*int_count*sizeof(uint32_t)); /* gic has #interrupt-cells=3 */
        continue;
      }
      else if(streq(prop_name, "linux,phandle")) /* Don't copy "linux,phandle", it's obsolete and we already use phandle */
      {
        printf("    - skipping 'linux,phandle' property\n");
        continue;
      }
      else if(streq(prop_name, "phandle")) /* Generate a new phandle so that it is unique in the dst device tree  */
      {
        printf("    = replacing 'phandle' property with a newly generated value \n");
        if(fdt_generate_phandle(fdt_dst, &prop_newphandle) < 0)
	{
	  printf("error: could not generate a new phandle for the copied node\n");
	  exit(-1);
	}
        prop_newphandle = (fdt32_to_cpu(prop_newphandle));
        fdt_setprop(fdt_dst, dst_newnode_offset, prop_name, &prop_newphandle, prop_len);
        continue;
      }
 #if 0
      if(prop_value_is_phandle(fdt_src, prop_value, prop_len))
      {
        printf("propvalue is likely a phandle\n");
      }
 #endif
      printf("    + copying property %s, len = %d \n", prop_name, prop_len);
      fdt_setprop(fdt_dst, dst_newnode_offset, prop_name, prop_value, prop_len);
    }
  }
  
  if ((prop_offset < 0) && (prop_offset != -FDT_ERR_NOTFOUND)) 
  {
    /*Error handling*/
    printf("%s(): warning: there was an error accessing a property of node\n", __func__);
    return NULL;
  }
  return fdt_dst;
}

/* Pack the fdt and write to file '@filename',
 * 
 * returns:
 *          The size of the packed fdt 
 */
int pack_and_save(void *fdt, char *filename)
{
  int packsize = 0, err = 0;
  err = fdt_pack(fdt);
  if (err)
    printf("fdt_pack(): %s", fdt_strerror(err));
  save_blob(filename, fdt);
  packsize = fdt_totalsize(fdt);
  return packsize;
}

int help()
{
  printf("Extract dtb nodes with compatible property COMPATIBLE from HOST_DTB_FILE\n");
  printf("and put them to EVASION_DTB_FILE (inplace). Or create a new generic node in EVASION_DTB_FILE\n");
  printf("in case EVASION_DTB_FILE has a specical value of 'none' \n\n");

  printf("usage: fdtextract -f HOST_DTB_FILE -t EVASION_DTB_FILE COMPATIBLE [COMPATIBLE [...]]\n\n");

  printf("Options:\n\n");
  printf("  -f DTB_FILE File from where to extract the device tree node \n");
  printf("              (can be \"none\" to indicate that a new generic node should be created)\n\n");
  printf("  -t DTB_FILE File where to add the device tree node (usually it's 'vexpress-v2p-ca9.dtb'\n\n");
  printf("  -n NODE_NAME Use this node name for a new generic node\n\n");
  printf("Examples:\n\n");
  printf("     fdtextract -f mt6765.dtb -t vexpress-v2p-ca9-kernel4.9.117.dtb \"mediatek,imgsys\"\n");
  printf("     fdtextract -f none -t vexpress-v2p-ca9-kernel4.9.117.dtb \"mediatek,mt8163-soc-pcm-voice-md2-bt\"\n");
  return 0;
}

int main(int argc, char **argv)
{
  int opt;
  int nnamelen = 0; /* A temp variable, reused for all nodes */
  const char *nname = NULL; /* A temp variable, reused for all nodes */
  char *dtb_host = NULL, *dtb_evasion = NULL; /* We read DTB's from these filenames */
  void *fdt_evasion, *fdt_host; /* Flattenned device trees in memory */
  int node_offset_in_host, node_offset_in_evasion;
  char *compatible = NULL; /* Compatibility property of the node */
  char *new_node_name = NULL; /* In case we want to create a new generic node, use this name. If not set, we'll use the name "generic_node_XXXX" */
  srand (time(NULL));
  //int flag_inplace = 0;

  while ((opt = getopt(argc, argv, "hf:t:n:")) != -1) {
    switch (opt) {
    case 'h':
        help();
	exit(0);
	break;
    case 'f':
        dtb_host = optarg;
        break;
    case 't':
        dtb_evasion = optarg;
        break;
    case 'n':
        new_node_name = optarg;
        break;
    default: /* '?' */
        printf("error: wrong arguments, use -h for help\n");
        exit(-1);
    }
  }

  if(!dtb_host || !dtb_evasion) {
    printf("error: please provide both host and evasion dtb files (or special 'none' for host dtb), -h for help\n");
    exit(-1);
  }

  if(dtb_host && new_node_name)
    printf("warning: new node name will be ignored, the original node name form the host kernel will be used\n");


  if (optind >= argc) {
    printf("error: please provide at least on compatible property, -h for help\n");
    exit(-1);
  }
  compatible = argv[optind];

  if(strnoteq(dtb_host, "none"))
  {
    /** 1. Make some preparations: ead dtb files, find note offset using compatibility property,
      *  Check if the evasion dtb already contains this node*/
    printf("Going to extract node '%s'\n", compatible);
    printf("from file: '%s' and inject it\n", dtb_host);
    printf("into file: '%s'\n\n",  dtb_evasion);
    //printf("[+] Loading host dtb '%s'\n", dtb_host);
    printf("[+] Loading dtb's: '%s', '%s'\n", dtb_host, dtb_evasion);
    fdt_host = load_blob(dtb_host);
    if(!fdt_host)
    {
      //printf("error: couldn't open host blob from \"%s\"(does file exist?)\n", dtb_host);
      exit(1);
    }
    //printf("[+] Loading evasion dtb '%s'\n", dtb_evasion);
    fdt_evasion = load_blob(dtb_evasion);
    if(!fdt_evasion)
    {
      //printf("error: couldn't open host blob from \"%s\"(does file exist?)\n", dtb_host);
      exit(1);
    }

    /* Find the device tree node used by the driver in the host device tree. We call it 'msm' node
        for historical reasons: our first target was msm kernel **/
    node_offset_in_host = fdt_node_offset_by_compatible(fdt_host, -1, compatible);
    if(node_offset_in_host<0)
    {
      printf("error: could not find requested node based on compatible property (%s) in the host device tree\n", compatible);
      exit(0);
    }

    /* Check if the evasion (vexpress) dtb file already contains the extracted node */
    node_offset_in_evasion = fdt_node_offset_by_compatible(fdt_evasion, -1, compatible);
    if(node_offset_in_evasion>=0)
    {
      printf("[-] error: the evasion dtb already contains node with compatibility property '%s'\n", compatible);
      exit(0);
    }

    nname = fdt_get_name(fdt_host, node_offset_in_host, &nnamelen);
    printf("[+] Found node '%s' (compatible = '%s') in the host dtb\n", nname, compatible);

    /** 2. Do the real work now.
     *  This function will a) copy fdt_evasion into memory, b) add the requested
     *  node from fdt_host to this copy **/
    void *fdt_alien_new = copy_node(fdt_evasion, fdt_host, node_offset_in_host, nname);  

    printf("[+] Backing up evasion dtb into 'backup.dtb'\n");
    OSCopyFile(dtb_evasion, "backup.dtb");
    printf("[+] Rewriting the original evasion dtb file\n");
    pack_and_save(fdt_alien_new, dtb_evasion);
    //printf("[+] Saving new result into %s\n", OUTNAME);
    //pack_and_save(fdt_alien_new, OUTNAME);
    free(fdt_alien_new);
  } else /* dtbhost is "none" which is used to indicate that we need to add a generic node with indicated compatibility property  */
  {
    /** 1. Make some preparations:  Check if the evasion dtb already contains this node*/
    printf("[+] Going to create a new node '%s' in file '%s'\n", compatible, dtb_evasion);
    printf("[+] Loading dtb: '%s'\n", dtb_evasion);
    fdt_evasion = load_blob(dtb_evasion);
    if(!fdt_evasion)
    {
      printf("error: couldn't open host blob from \"%s\"(does file exist?)\n", dtb_host);
      exit(1);
    }

#if 0 // ivanp: we moved this check inside add_generic_node() since at this point <compatible> may contain '@i2c' at the end
    /* Check if the evasion (vexpress) dtb file already contains the extracted node */
    node_offset_in_evasion = fdt_node_offset_by_compatible(fdt_evasion, -1, compatible);
    if(node_offset_in_evasion>=0)
    {
      printf("[-] error: the evasion dtb already contains node with compatibility property '%s'\n", compatible);
      exit(0);
    }
#endif


    /** 2. Do the real work now.
     *  This function will a) copy fdt_evasion into memory, b) add a new node with requested
     *  compatibility property **/
    void *fdt_alien_new = add_generic_node(fdt_evasion, compatible, new_node_name);  
    if(!fdt_alien_new)
      exit(-1);

    printf("[+] Backing up evasion dtb into 'backup.dtb'\n");
    OSCopyFile(dtb_evasion, "backup.dtb");
    printf("[+] Rewriting the original evasion dtb file\n");
    pack_and_save(fdt_alien_new, dtb_evasion);
    free(fdt_alien_new);
    
  }
}
