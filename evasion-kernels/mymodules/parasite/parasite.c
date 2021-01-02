#include <linux/init.h>          
#include <linux/module.h>        
#include <linux/device.h>        
#include <linux/kernel.h>        
#include <linux/fs.h>            
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include <asm/uaccess.h>         

#define  SELF_DEVICE_NAME "parasite0"   
#define  SELF_CLASS_NAME  "paras0"       
#define  PARASITE_DEVICE_NAME "parasite1"   
#define  PARASITE_CLASS_NAME  "paras1"       

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ivanp");
MODULE_DESCRIPTION("A parasite char driver to hook open and ioctl handlers of other drivers");
MODULE_VERSION("0.1");

char funcprotos[] __attribute__((section("protos"))) = "\x00";

static int    majorNumber;
//static char   message[256] = "Hello";
//static int    numberOpens = 0;
static struct class*  selfClass  = NULL;
static struct device* selfDevice = NULL;
static struct class*  parasiteClass  = NULL;
static struct device* parasiteDevice = NULL;

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static int dev_default(struct inode *inodep, struct file *filep);

static int     dev_open_stub(struct inode *, struct file *);
static int     dev_close_stub(struct inode *, struct file *);
static ssize_t dev_read_stub(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write_stub(struct file *, const char *, size_t, loff_t *);

static struct file_operations self_fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

static struct file_operations parasite_fops =
{
   .open = dev_open_stub,
   .read = dev_read_stub,
   .write = dev_write_stub,
   .unlocked_ioctl = dev_default,
   .release = dev_close_stub,
};


static int dev_default(struct inode *inodep, struct file *filep){
  printk("PARASITE DEFAULT HANDLER!\n");
  return 0;
}
EXPORT_SYMBOL(dev_default);

static ssize_t dev_write_stub(struct file *filep, const char *buffer, size_t len, loff_t *offset){
  printk("PARASITE DEFAULT WRITE HANDLER!\n");
  return len;
}
EXPORT_SYMBOL(dev_write_stub);

static ssize_t dev_read_stub(struct file *filep, char *buffer, size_t len, loff_t *offset){
  printk("PARASITE DEFAULT READ HANDLER!\n");
  return len;
}
EXPORT_SYMBOL(dev_read_stub);

static int dev_close_stub(struct inode *inodep, struct file *filep){
  printk("PARASITE DEFAULT CLOSE HANDLER!\n");
  return 0;
}
EXPORT_SYMBOL(dev_close_stub);

static int dev_open_stub(struct inode *inodep, struct file *filep){
   return 0;
}
EXPORT_SYMBOL(dev_open_stub);


/* In this function we create a char device using which we can
   tell the parasite driver which function to hook */
static int __init parasite_init(void){
   printk("parasite: Initializing\n");

   // Try to dynamically allocate a major number for the device
   majorNumber = register_chrdev(0, SELF_DEVICE_NAME, &self_fops);
   if (majorNumber<0){
      printk("parasite failed to register a major number\n");
      return majorNumber;
   }
   printk("parasite: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   selfClass = class_create(THIS_MODULE, SELF_CLASS_NAME);
   if (IS_ERR(selfClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, SELF_DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(selfClass);          // Correct way to return an error on a pointer
   }
   printk("parasite: device class registered correctly\n");

   // Register the device driver
   selfDevice = device_create(selfClass, NULL, MKDEV(majorNumber, 0), NULL, SELF_DEVICE_NAME);
   if (IS_ERR(selfDevice)){               // Clean up if there is an error
      class_destroy(selfClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, SELF_DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(selfDevice);
   }
   printk("parasite: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

int create_parasite_dev()
{
   printk(KERN_INFO "parasite: Initializing parasite chardev\n");

   // Try to dynamically allocate a major number for the device
   majorNumber = register_chrdev(0, PARASITE_DEVICE_NAME, &parasite_fops);
   if (majorNumber<0){
      printk("parasite failed to register a major number for parasite device\n");
      return majorNumber;
   }
   printk(KERN_INFO "parasite: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   parasiteClass = class_create(THIS_MODULE, PARASITE_CLASS_NAME);
   if (IS_ERR(parasiteClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, PARASITE_DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(parasiteClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "parasite: device class registered correctly\n");

   // Register the device driver
   parasiteDevice = device_create(parasiteClass, NULL, MKDEV(majorNumber, 0), NULL, PARASITE_DEVICE_NAME);
   if (IS_ERR(parasiteDevice)){               // Clean up if there is an error
      class_destroy(parasiteClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, PARASITE_DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(parasiteDevice);
   }
   printk(KERN_INFO "parasite: device class created correctly\n"); // Made it! device was initialized
   return 0;

}

static void __exit parasite_exit(void){
   device_destroy(selfClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(selfClass);                          // unregister the device class
   class_destroy(selfClass);                             // remove the device class
   unregister_chrdev(majorNumber, SELF_DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "parasite: Goodbye from the LKM!\n");
}


/* Nothing to do here, just open the device */
static int dev_open(struct inode *inodep, struct file *filep){
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   // char *c = (char *)0x10;
   // void *stuff;
   return 0;
   // printk(KERN_INFO "parasite: dev_read(): user buffer is at %p\n", buffer);
   // //stuff = kmalloc(32,GFP_KERNEL);
   // stuff = vmalloc(4096);
   // printk(KERN_INFO "parasite: dev_read(): user buffer is at %p\n", buffer);
   // printk(KERN_INFO "parasite: dev_read(): message is %s\n", message);
   // if(strncmp(message, "bug!",4) == 0)
   // {
   //   //printk("I got: %zu bytes of memory\n", ksize(stuff));
   //   //*((char *)stuff) = 'a';
   //   *c = 1;
   // }
   // else
   //   printk(KERN_INFO "parasite: no bug for you today!\n");
   // //kfree(stuff);
   // vfree(stuff);
   // //if(buffer[0] > 'A')
   // //  *c = 1;
   // //if(buffer[0] > 'Z')
   // //  *c = 2;
   // //if((buffer[0] >= 3) && (buffer[0] <= 30))
   // //  *c = 3;
   // copy_to_user(buffer, message, len);
   return 0;
}

#define OPEN 0
#define READ 1
#define WRITE 2
#define IOCTL 3
#define CLOSE 4
/* This is where we hook other module's open and ioctl functions.
 * 
 *  @param buffer Should contain a string that specifies two function names:
 *                open and ioctl handerls in another module. Function names are
 *                separated by space. Order matters.
*/
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   char msg[256];
   char *open_name;
   char *ioctl_name;
   char *release_name;
   unsigned long open_addr = 0;
   unsigned long read_addr = 0;
   unsigned long write_addr = 0;
   unsigned long ioctl_addr = 0;
   unsigned long release_addr = 0;
   char *p; /* used when parsing the input string in a loop */
   char *fnames[5];
   int i;

   /** FIND FUNCS **/
   if(len >= 256)
   {
     printk("parasite: input string should be less than 256, aborting\n");
     return -1;
   }
   if(copy_from_user(msg, buffer, len))
   {
     printk("parasite: copy_from_user failed, aborting\n");
     return -1;
   }
   msg[len] = '\0';
   if(msg[len-1] == '\n')
     msg[len-1] = '\0';

   /* "open read write ioctl close" */
   p = msg;
   i = 0;
   while(p && (p < msg+len) && (i<5))
   {
     fnames[i] = p; 

     p = strchr(p, ' ');
     if(!p)
       break;
     *p = '\0';
     p++;
     i++;
   }
   if(i<4)
   {
     printk("parasite: input string should contain five (5) function names separate by spaces: open read write ioctl close\n", i);
     printk("parasite: I found only %d spaces, aborting\n", i);
     return -1;
   }

   printk("parasite: open=<%s>, read=<%s>, write=<%s>, ioctl=<%s>, close_name=<%s>\n", 
                fnames[OPEN], fnames[READ], fnames[WRITE], fnames[IOCTL], fnames[CLOSE]);
   
   release_addr = kallsyms_lookup_name(fnames[CLOSE]);
   open_addr = kallsyms_lookup_name(fnames[OPEN]);
   read_addr = kallsyms_lookup_name(fnames[READ]);
   write_addr = kallsyms_lookup_name(fnames[WRITE]);
   ioctl_addr = kallsyms_lookup_name(fnames[IOCTL]);

   printk("parasite: open@0x%x, read@0x%x, write@0x%x, ioctl@0x%x, close_name@0x%x\n", 
                open_addr, read_addr, write_addr, ioctl_addr, release_addr);
   if (!open_addr || !read_addr || !write_addr || !ioctl_addr || !release_addr)
   {
     printk("parasite: Could not resolve function name to addresses (did you load the module under test?), aborting\n");
     return -1;
   }

   printk("parasite: Successfully resolved functions\n");

   /** CREATE CHR DEV **/
   parasite_fops.open = open_addr;
   parasite_fops.read = read_addr;
   parasite_fops.write = write_addr;
   parasite_fops.unlocked_ioctl = ioctl_addr;
   parasite_fops.release = release_addr;
   if(create_parasite_dev())
     printk("parasite: failed to create parasite device!\n");

   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "parasite: Device successfully closed\n");
   return 0;
}

module_init(parasite_init);
module_exit(parasite_exit);
