#include <linux/init.h>          
#include <linux/module.h>        
#include <linux/device.h>        
#include <linux/kernel.h>        
#include <linux/fs.h>            
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include <asm/uaccess.h>         

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ivanp");
MODULE_DESCRIPTION("***");
MODULE_VERSION("0.2");

void *pdev_check(struct platform_device *pdev, struct device **dev) 
{
  void **p = (void **)42;
  pdev->id = sizeof(int);
  *dev = &pdev->dev;
  *p =  pdev->dev.of_node;
  return pdev->dev.release;
}

//uint32_t quasi_print(uint32_t base, uint32_t address)
#define INIT_TOKEN 0
#define TOKEN_RLOCK1 500
#define TOKEN_RLOCK2 1000
#define TOKEN_RLOCK3 1500
#define TOKEN_RANGE1 2000
uint32_t noinline quasi_print(uint32_t offset, int token);
//{
//  asm ("");
//  return 1;
//}

#define BASE 42
void *dev_check(struct device *dev) 
{
  struct device *dev_local = 0;
  quasi_print((uint32_t)&dev_local->parent,INIT_TOKEN+0);
  quasi_print((uint32_t)&dev_local->p,INIT_TOKEN+1);
  quasi_print((uint32_t)&dev_local->kobj,INIT_TOKEN+2);
  // { Members of 'struct kobject kobj'
      quasi_print((uint32_t)&dev_local->kobj.name,INIT_TOKEN+3);
      quasi_print((uint32_t)&dev_local->kobj.entry.next,INIT_TOKEN+4);
      quasi_print((uint32_t)&dev_local->kobj.entry.prev,INIT_TOKEN+5);
      quasi_print((uint32_t)&dev_local->kobj.parent,INIT_TOKEN+6);
      quasi_print((uint32_t)&dev_local->kobj.kset,INIT_TOKEN+7);
      quasi_print((uint32_t)&dev_local->kobj.ktype,INIT_TOKEN+8);
      quasi_print((uint32_t)&dev_local->kobj.sd,INIT_TOKEN+9);
      quasi_print((uint32_t)&dev_local->kobj.kref,INIT_TOKEN+10);
      #ifdef CONFIG_DEBUG_KOBJECT_RELEASE
      quasi_print((uint32_t)&dev_local->kobj.release,INIT_TOKEN+11);
      #endif
  // } Back to 'struct device'
  quasi_print((uint32_t)&dev_local->init_name,INIT_TOKEN+12);
  quasi_print((uint32_t)&dev_local->type,INIT_TOKEN+13);
  quasi_print((uint32_t)&dev_local->mutex,INIT_TOKEN+14);
  // { Members of  'struct mutex mutex'
      quasi_print((uint32_t)&dev_local->mutex.count,INIT_TOKEN+15);
      quasi_print((uint32_t)&dev_local->mutex.wait_lock,INIT_TOKEN+16);
      // { Members of 'struct spintlock_t wait_lock'
          quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock,INIT_TOKEN+17);
          // { Members of 'struct raw_spinlock rlock'
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.raw_lock,TOKEN_RLOCK1+1);
              #ifdef CONFIG_GENERIC_LOCKBREAK
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.break_lock,TOKEN_RLOCK1+2);
	      #endif
              #ifdef CONFIG_DEBUG_SPINLOCK
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.magic,TOKEN_RLOCK1+3);
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.owner_cpu,TOKEN_RLOCK1+4);
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.owner,TOKEN_RLOCK1+5);
	      #endif
              #ifdef CONFIG_DEBUG_LOCK_ALLOC
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.dep_map,TOKEN_RLOCK1+6);
	      // { Members of 'struct lockdep_map dep_map'
                  quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.dep_map.key,TOKEN_RLOCK1+7);
                  quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.dep_map.class_cache,TOKEN_RLOCK1+8);
                  quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.dep_map.name,TOKEN_RLOCK1+9);
                  #ifdef CONFIG_LOCK_STAT
                  quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.dep_map.cpu,TOKEN_RLOCK1+10);
                  quasi_print((uint32_t)&dev_local->mutex.wait_lock.rlock.dep_map.ip,TOKEN_RLOCK1+11);
	          #endif
	      // } Back to 'struct raw_spinlock rlock'
	      #endif
	  // } Back to 'struct spintlock_t wait_lock'
          #ifdef CONFIG_DEBUG_LOCK_ALLOC
          # define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
          quasi_print((uint32_t)&dev_local->mutex.wait_lock.__padding,INIT_TOKEN+18);
          quasi_print((uint32_t)&dev_local->mutex.wait_lock.dep_map,INIT_TOKEN+19);
	  // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.dep_map.key,INIT_TOKEN+20); // ### 20 ### //
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.dep_map.class_cache,INIT_TOKEN+21);
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.dep_map.name,INIT_TOKEN+22);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.dep_map.cpu,INIT_TOKEN+23);
              quasi_print((uint32_t)&dev_local->mutex.wait_lock.dep_map.ip,INIT_TOKEN+24);
	      #endif
	  // } Back to 'struct spintlock_t wait_lock'
	  #endif
      // } Back to 'struct mutex mutex'
      quasi_print((uint32_t)&dev_local->mutex.wait_list,INIT_TOKEN+25);
      quasi_print((uint32_t)&dev_local->mutex.wait_list.next,INIT_TOKEN+26);
      quasi_print((uint32_t)&dev_local->mutex.wait_list.prev,INIT_TOKEN+27);
      #if defined(CONFIG_DEBUG_MUTEXES) || defined(CONFIG_MUTEX_SPIN_ON_OWNER)
      quasi_print((uint32_t)&dev_local->mutex.owner,TOKEN_RANGE1+2);
      #endif
      #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
      quasi_print((uint32_t)&dev_local->mutex.osq,INIT_TOKEN+28);
      #endif
      #ifdef CONFIG_DEBUG_MUTEXES
      quasi_print((uint32_t)&dev_local->mutex.magic,INIT_TOKEN+29);
      #endif
      #ifdef CONFIG_DEBUG_LOCK_ALLOC
      quasi_print((uint32_t)&dev_local->mutex.dep_map,INIT_TOKEN+30);
	  // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&dev_local->mutex.dep_map.key,INIT_TOKEN+31); // ### 20 ### //
              quasi_print((uint32_t)&dev_local->mutex.dep_map.class_cache,INIT_TOKEN+32);
              quasi_print((uint32_t)&dev_local->mutex.dep_map.name,INIT_TOKEN+33);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&dev_local->mutex.dep_map.cpu,INIT_TOKEN+34);
              quasi_print((uint32_t)&dev_local->mutex.dep_map.ip,INIT_TOKEN+35);
	      #endif
	  // } Back to 'struct mutex mutex'
      #endif
  // } Back to 'struct device'
  quasi_print((uint32_t)&dev_local->bus,INIT_TOKEN+36);
  quasi_print((uint32_t)&dev_local->driver,INIT_TOKEN+37);
  quasi_print((uint32_t)&dev_local->platform_data,INIT_TOKEN+38);
  quasi_print((uint32_t)&dev_local->driver_data,INIT_TOKEN+39);
  quasi_print((uint32_t)&dev_local->power,INIT_TOKEN+40);
  // { Members of  'struct dev_pm_info power'
      quasi_print((uint32_t)&dev_local->power.power_state,INIT_TOKEN+41);
      quasi_print((uint32_t)&dev_local->power.lock,INIT_TOKEN+42);
      // { Members of 'spintlock_t lock'
          quasi_print((uint32_t)&dev_local->power.lock.rlock,INIT_TOKEN+43);
          // { Members of 'struct raw_spinlock rlock'
              quasi_print((uint32_t)&dev_local->power.lock.rlock.raw_lock,TOKEN_RLOCK2+1);
              #ifdef CONFIG_GENERIC_LOCKBREAK
              quasi_print((uint32_t)&dev_local->power.lock.rlock.break_lock,TOKEN_RLOCK2+2);
	      #endif
              #ifdef CONFIG_DEBUG_SPINLOCK
              quasi_print((uint32_t)&dev_local->power.lock.rlock.magic,TOKEN_RLOCK2+3);
              quasi_print((uint32_t)&dev_local->power.lock.rlock.owner_cpu,TOKEN_RLOCK2+4);
              quasi_print((uint32_t)&dev_local->power.lock.rlock.owner,TOKEN_RLOCK2+5);
	      #endif
              #ifdef CONFIG_DEBUG_LOCK_ALLOC
              quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map,TOKEN_RLOCK2+6);
	      // { Members of 'struct lockdep_map dep_map'
                  quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map.key,TOKEN_RLOCK2+7);
                  quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map.class_cache,TOKEN_RLOCK2+8);
                  quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map.name,TOKEN_RLOCK2+9);
                  #ifdef CONFIG_LOCK_STAT
                  quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map.cpu,TOKEN_RLOCK2+10);
                  quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map.ip,TOKEN_RLOCK2+11);
	          #endif
	      // } Back to 'struct raw_spinlock rlock'
	      #endif
	  // } Back to 'spintlock_t lock'
          #ifdef CONFIG_DEBUG_LOCK_ALLOC
          # define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
          quasi_print((uint32_t)&dev_local->power.lock.__padding,INIT_TOKEN+44);
          quasi_print((uint32_t)&dev_local->power.lock.dep_map,INIT_TOKEN+45);
	  // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&dev_local->power.lock.dep_map.key,INIT_TOKEN+46); // ### 20 ### //
              quasi_print((uint32_t)&dev_local->power.lock.dep_map.class_cache,INIT_TOKEN+47);
              quasi_print((uint32_t)&dev_local->power.lock.dep_map.name,INIT_TOKEN+48);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&dev_local->power.lock.dep_map.cpu,INIT_TOKEN+49);
              quasi_print((uint32_t)&dev_local->power.lock.dep_map.ip,INIT_TOKEN+50);
	      #endif
	  // } Back to 'spintlock_t wait_lock'
	  #endif
      // } Back to 'struct dev_pm_info power'
      #ifdef CONFIG_PM_SLEEP
      quasi_print((uint32_t)&dev_local->power.entry,INIT_TOKEN+51);
      quasi_print((uint32_t)&dev_local->power.entry.next,INIT_TOKEN+52);
      quasi_print((uint32_t)&dev_local->power.entry.prev,INIT_TOKEN+53);
      quasi_print((uint32_t)&dev_local->power.completion,INIT_TOKEN+54);
      // { Members of 'struct completion completion'
          quasi_print((uint32_t)&dev_local->power.completion.done,INIT_TOKEN+55);
          quasi_print((uint32_t)&dev_local->power.completion.wait,TOKEN_RANGE1+1);
          // { Members of 'wait_queue_head_t wait'
              quasi_print((uint32_t)&dev_local->power.completion.wait.lock,INIT_TOKEN+56);
              // { Members of 'spintlock_t lock'
                  quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock,INIT_TOKEN+57);
                  // { Members of 'struct raw_spinlock rlock'
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.raw_lock,TOKEN_RLOCK3+1);
                      #ifdef CONFIG_GENERIC_LOCKBREAK
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.break_lock,TOKEN_RLOCK3+2);
	              #endif
                      #ifdef CONFIG_DEBUG_SPINLOCK
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.magic,TOKEN_RLOCK3+3);
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.owner_cpu,TOKEN_RLOCK3+4);
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.owner,TOKEN_RLOCK3+5);
	              #endif
                      #ifdef CONFIG_DEBUG_LOCK_ALLOC
                      quasi_print((uint32_t)&dev_local->power.lock.rlock.dep_map,TOKEN_RLOCK3+6);
	              // { Members of 'struct lockdep_map dep_map'
                          quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.dep_map.key,TOKEN_RLOCK3+7);
                          quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.dep_map.class_cache,TOKEN_RLOCK3+8);
                          quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.dep_map.name,TOKEN_RLOCK3+9);
                          #ifdef CONFIG_LOCK_STAT
                          quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.dep_map.cpu,TOKEN_RLOCK3+10);
                          quasi_print((uint32_t)&dev_local->power.completion.wait.lock.rlock.dep_map.ip,TOKEN_RLOCK3+11);
	                  #endif
	              // } Back to 'struct raw_spinlock rlock'
	              #endif
	          // } Back to 'spintlock_t lock'
                  #ifdef CONFIG_DEBUG_LOCK_ALLOC
                  # define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
                  quasi_print((uint32_t)&dev_local->power.completion.wait.lock.__padding,INIT_TOKEN+58);
                  quasi_print((uint32_t)&dev_local->power.completion.wait.lock.dep_map,INIT_TOKEN+59);
                  // { Members of 'struct lockdep_map dep_map'
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.dep_map.key,INIT_TOKEN+60); // ### 20 ### //
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.dep_map.class_cache,INIT_TOKEN+61);
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.dep_map.name,INIT_TOKEN+62);
                      #ifdef CONFIG_LOCK_STAT
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.dep_map.cpu,INIT_TOKEN+63);
                      quasi_print((uint32_t)&dev_local->power.completion.wait.lock.dep_map.ip,INIT_TOKEN+64);
                      #endif
                  // } Back to 'spintlock_t lock'
                  #endif
              // } Back to 'wait_queue_head_t wait'
              quasi_print((uint32_t)&dev_local->power.completion.wait.task_list,INIT_TOKEN+65);
              quasi_print((uint32_t)&dev_local->power.completion.wait.task_list.next,INIT_TOKEN+66);
              quasi_print((uint32_t)&dev_local->power.completion.wait.task_list.prev,INIT_TOKEN+67);
          // } Back to 'struct completion completion'
      // } Back to 'struct dev_pm_info power'
      quasi_print((uint32_t)&dev_local->power.wakeup,INIT_TOKEN+68);
      #else // CONFIG_PM_SLEEP
      #endif
      #ifdef CONFIG_PM
      quasi_print((uint32_t)&dev_local->power.suspend_timer,INIT_TOKEN+69);
      // { Members of 'struct timer_list suspend_timer'
          quasi_print((uint32_t)&dev_local->power.suspend_timer.entry,INIT_TOKEN+70);
          quasi_print((uint32_t)&dev_local->power.suspend_timer.expires,INIT_TOKEN+71);
          quasi_print((uint32_t)&dev_local->power.suspend_timer.function,INIT_TOKEN+72);
          quasi_print((uint32_t)&dev_local->power.suspend_timer.data,INIT_TOKEN+73);
          quasi_print((uint32_t)&dev_local->power.suspend_timer.flags,INIT_TOKEN+74);
          #ifdef CONFIG_TIMER_STATS
              quasi_print((uint32_t)&dev_local->power.suspend_timer.start_pid,INIT_TOKEN+75);
              quasi_print((uint32_t)&dev_local->power.suspend_timer.start_site,INIT_TOKEN+76);
              quasi_print((uint32_t)&dev_local->power.suspend_timer.start_comm,INIT_TOKEN+77);
	  #endif
          #ifdef CONFIG_LOCKDEP
	      // Includes CONFIG_LOCK_STAT
              quasi_print((uint32_t)&dev_local->power.suspend_timer.lockdep_map,INIT_TOKEN+78);
	  #endif
      // } Back to 'struct dev_pm_info power'
      quasi_print((uint32_t)&dev_local->power.timer_expires,INIT_TOKEN+79); // includes CONFIG_LOCKDEP
      quasi_print((uint32_t)&dev_local->power.work,INIT_TOKEN+80);
      quasi_print((uint32_t)&dev_local->power.wait_queue,INIT_TOKEN+81);
      quasi_print((uint32_t)&dev_local->power.wakeirq,TOKEN_RANGE1+3);
      quasi_print((uint32_t)&dev_local->power.child_count,TOKEN_RANGE1+4);
      quasi_print((uint32_t)&dev_local->power.accounting_timestamp,INIT_TOKEN+82);
      #endif // CONFIG_PM
      quasi_print((uint32_t)&dev_local->power.qos,TOKEN_RANGE1+5);
  // } Back to 'struct device'
  quasi_print((uint32_t)&dev_local->pm_domain,INIT_TOKEN+83);
  #ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
  quasi_print((uint32_t)&dev_local->msi_domain,INIT_TOKEN+84);
  #endif
  #ifdef PINCTRL
  quasi_print((uint32_t)&dev_local->pins,TOKEN_RANGE1+6);
  #endif
  #ifdef CONFIG_GENERIC_MSI_IRQ
  quasi_print((uint32_t)&dev_local->msi_list,INIT_TOKEN+85);
  #endif
  #ifdef CONFIG_NUMA
  quasi_print((uint32_t)&dev_local->numa_node,INIT_TOKEN+86);
  #endif
  quasi_print((uint32_t)&dev_local->dma_mask,INIT_TOKEN+87);
  quasi_print((uint32_t)&dev_local->coherent_dma_mask,INIT_TOKEN+88);
  quasi_print((uint32_t)&dev_local->dma_pfn_offset,INIT_TOKEN+89);
  quasi_print((uint32_t)&dev_local->dma_parms,INIT_TOKEN+90);
  quasi_print((uint32_t)&dev_local->dma_pools,INIT_TOKEN+91);
  quasi_print((uint32_t)&dev_local->dma_mem,INIT_TOKEN+92);
  #ifdef CONFIG_DMA_CMA
  quasi_print((uint32_t)&dev_local->cma_area,INIT_TOKEN+93);
  #endif
  quasi_print((uint32_t)&dev_local->archdata,INIT_TOKEN+94);
  // { Members of  'struct dev_archdata	archdata'
      quasi_print((uint32_t)&dev_local->archdata.dma_ops,INIT_TOKEN+95);
      #ifdef CONFIG_DMABOUNCE
      quasi_print((uint32_t)&dev_local->archdata.dmabounce,INIT_TOKEN+96);
      #endif
      #ifdef CONFIG_IOMMU_API
      quasi_print((uint32_t)&dev_local->archdata.iommu,INIT_TOKEN+97);
      #endif
      #ifdef CONFIG_ARM_DMA_USE_IOMMU
      quasi_print((uint32_t)&dev_local->archdata.mapping,INIT_TOKEN+98);
      #endif
      quasi_print((uint32_t)&dev_local->archdata.dma_coherent,INIT_TOKEN+99);
  // } Back to 'struct device'



  //quasi_print(&dev_local->p-dev_local);
  //dev_local->parent =          (void *)BASE+0;
  //dev_local->p =               (void *)BASE+1;
  ////struct kobject kobj
  //dev_local->kobj.name =       (void *)BASE+2;
  //dev_local->kobj.entry.next = (void *)BASE+3;
  //dev_local->kobj.entry.prev = (void *)BASE+4;
  return NULL;
}

void *file_check(struct file *filep){
  struct file *filep_local = 0;
  quasi_print((uint32_t)&filep_local->f_u,INIT_TOKEN+0);
  quasi_print((uint32_t)&filep_local->f_path,INIT_TOKEN+1);
  quasi_print((uint32_t)&filep_local->f_inode,INIT_TOKEN+2);
  quasi_print((uint32_t)&filep_local->f_op,INIT_TOKEN+3);
  quasi_print((uint32_t)&filep_local->f_lock,INIT_TOKEN+4); // its size depends on CONFIG_GENERIC_LOCKBREAK, CONFIG_DEBUG_SPINLOCK, CONFIG_DEBUG_LOCK_ALLOC
  // { Members of 'spintlock_t f_lock'
      quasi_print((uint32_t)&filep_local->f_lock.rlock,INIT_TOKEN+5);
      // { Members of 'struct raw_spinlock rlock'
          quasi_print((uint32_t)&filep_local->f_lock.rlock.raw_lock,INIT_TOKEN+6);
          #ifdef CONFIG_GENERIC_LOCKBREAK
          quasi_print((uint32_t)&filep_local->f_lock.rlock.break_lock,INIT_TOKEN+7);
          #endif
          #ifdef CONFIG_DEBUG_SPINLOCK
          quasi_print((uint32_t)&filep_local->f_lock.rlock.magic,INIT_TOKEN+8);
          quasi_print((uint32_t)&filep_local->f_lock.rlock.owner_cpu,INIT_TOKEN+9);
          quasi_print((uint32_t)&filep_local->f_lock.rlock.owner,INIT_TOKEN+10);
          #endif
          #ifdef CONFIG_DEBUG_LOCK_ALLOC
          quasi_print((uint32_t)&filep_local->f_lock.rlock.dep_map,INIT_TOKEN+11);
          // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&filep_local->f_lock.rlock.dep_map.key,INIT_TOKEN+12);
              quasi_print((uint32_t)&filep_local->f_lock.rlock.dep_map.class_cache,INIT_TOKEN+13);
              quasi_print((uint32_t)&filep_local->f_lock.rlock.dep_map.name,INIT_TOKEN+14);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&filep_local->f_lock.rlock.dep_map.cpu,INIT_TOKEN+15);
              quasi_print((uint32_t)&filep_local->f_lock.rlock.dep_map.ip,INIT_TOKEN+16);
              #endif
          // } Back to 'struct raw_spinlock rlock'
          #endif
      // } Back to 'spintlock_t f_lock'
      #ifdef CONFIG_DEBUG_LOCK_ALLOC
      # define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
      quasi_print((uint32_t)&filep_local->f_lock.__padding,INIT_TOKEN+17);
      quasi_print((uint32_t)&filep_local->f_lock.dep_map,INIT_TOKEN+18);
      // { Members of 'struct lockdep_map dep_map'
          quasi_print((uint32_t)&filep_local->f_lock.dep_map.key,INIT_TOKEN+19);
          quasi_print((uint32_t)&filep_local->f_lock.dep_map.class_cache,INIT_TOKEN+20);
          quasi_print((uint32_t)&filep_local->f_lock.dep_map.name,INIT_TOKEN+21);
          #ifdef CONFIG_LOCK_STAT
          quasi_print((uint32_t)&filep_local->f_lock.dep_map.cpu,INIT_TOKEN+22);
          quasi_print((uint32_t)&filep_local->f_lock.dep_map.ip,INIT_TOKEN+23);
          #endif
      // } Back to 'spintlock_t wait_lock'
      #endif
  // } Back to filep_local'
  quasi_print((uint32_t)&filep_local->f_count,INIT_TOKEN+24);
  quasi_print((uint32_t)&filep_local->f_flags,INIT_TOKEN+25);
  quasi_print((uint32_t)&filep_local->f_mode,INIT_TOKEN+26);
  quasi_print((uint32_t)&filep_local->f_pos_lock,INIT_TOKEN+27);
  // { Members of  'struct mutex f_pos_lock'
      quasi_print((uint32_t)&filep_local->f_pos_lock.count,INIT_TOKEN+28);
      quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock,INIT_TOKEN+29);
      // { Members of 'struct spintlock_t wait_lock'
          quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock,INIT_TOKEN+30);
          // { Members of 'struct raw_spinlock rlock'
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.raw_lock,INIT_TOKEN+31);
              #ifdef CONFIG_GENERIC_LOCKBREAK
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.break_lock,INIT_TOKEN+32);
	      #endif
              #ifdef CONFIG_DEBUG_SPINLOCK
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.magic,INIT_TOKEN+33);
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.owner_cpu,INIT_TOKEN+34);
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.owner,INIT_TOKEN+35);
	      #endif
              #ifdef CONFIG_DEBUG_LOCK_ALLOC
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.dep_map,INIT_TOKEN+36);
	      // { Members of 'struct lockdep_map dep_map'
                  quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.dep_map.key,INIT_TOKEN+37);
                  quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.dep_map.class_cache,INIT_TOKEN+38);
                  quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.dep_map.name,INIT_TOKEN+39);
                  #ifdef CONFIG_LOCK_STAT
                  quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.dep_map.cpu,INIT_TOKEN+40);
                  quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.rlock.dep_map.ip,INIT_TOKEN+41);
	          #endif
	      // } Back to 'struct raw_spinlock rlock'
	      #endif
	  // } Back to 'struct spintlock_t wait_lock'
          #ifdef CONFIG_DEBUG_LOCK_ALLOC
          # define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
          quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.__padding,INIT_TOKEN+42);
          quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.dep_map,INIT_TOKEN+43);
	  // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.dep_map.key,INIT_TOKEN+44); // ### 20 ### //
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.dep_map.class_cache,INIT_TOKEN+45);
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.dep_map.name,INIT_TOKEN+46);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.dep_map.cpu,INIT_TOKEN+47);
              quasi_print((uint32_t)&filep_local->f_pos_lock.wait_lock.dep_map.ip,INIT_TOKEN+48);
	      #endif
	  // } Back to 'struct spintlock_t wait_lock'
	  #endif
      // } Back to 'struct mutex f_pos_lock'
      quasi_print((uint32_t)&filep_local->f_pos_lock.wait_list,INIT_TOKEN+49);
      quasi_print((uint32_t)&filep_local->f_pos_lock.wait_list.next,INIT_TOKEN+50);
      quasi_print((uint32_t)&filep_local->f_pos_lock.wait_list.prev,INIT_TOKEN+51);
      #if defined(CONFIG_DEBUG_MUTEXES) || defined(CONFIG_MUTEX_SPIN_ON_OWNER)
      quasi_print((uint32_t)&filep_local->f_pos_lock.owner,INIT_TOKEN+52);
      #endif
      #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
      quasi_print((uint32_t)&filep_local->f_pos_lock.osq,INIT_TOKEN+53);
      #endif
      #ifdef CONFIG_DEBUG_MUTEXES
      quasi_print((uint32_t)&filep_local->f_pos_lock.magic,INIT_TOKEN+54);
      #endif
      #ifdef CONFIG_DEBUG_LOCK_ALLOC
      quasi_print((uint32_t)&filep_local->f_pos_lock.dep_map,INIT_TOKEN+55);
	  // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&filep_local->f_pos_lock.dep_map.key,INIT_TOKEN+56); // ### 20 ### //
              quasi_print((uint32_t)&filep_local->f_pos_lock.dep_map.class_cache,INIT_TOKEN+57);
              quasi_print((uint32_t)&filep_local->f_pos_lock.dep_map.name,INIT_TOKEN+58);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&filep_local->f_pos_lock.dep_map.cpu,INIT_TOKEN+59);
              quasi_print((uint32_t)&filep_local->f_pos_lock.dep_map.ip,INIT_TOKEN+60);
	      #endif
	  // } Back to 'struct mutex f_pos_lock'
      #endif
  // } Back to 'struct file filep_local'
  quasi_print((uint32_t)&filep_local->f_pos,INIT_TOKEN+61);
  quasi_print((uint32_t)&filep_local->f_owner,INIT_TOKEN+62);
  // { Members of 'struct fown_struct f_owner'
      quasi_print((uint32_t)&filep_local->f_owner.lock,INIT_TOKEN+63);
      // { Members of 'struct rw_lock lock'
          quasi_print((uint32_t)&filep_local->f_owner.lock.raw_lock,INIT_TOKEN+64);
          #ifdef CONFIG_GENERIC_LOCKBREAK
          quasi_print((uint32_t)&filep_local->f_owner.lock.break_lock,INIT_TOKEN+65);
          #endif
          #ifdef CONFIG_DEBUG_SPINLOCK
          quasi_print((uint32_t)&filep_local->f_owner.lock.magic,INIT_TOKEN+66);
          quasi_print((uint32_t)&filep_local->f_owner.lock.owner_cpu,INIT_TOKEN+67);
          quasi_print((uint32_t)&filep_local->f_owner.lock.owner,INIT_TOKEN+68);
          #endif
          #ifdef CONFIG_DEBUG_LOCK_ALLOC
          quasi_print((uint32_t)&filep_local->f_owner.lock.dep_map,INIT_TOKEN+69);
          // { Members of 'struct lockdep_map dep_map'
              quasi_print((uint32_t)&filep_local->f_owner.lock.dep_map.key,INIT_TOKEN+70);
              quasi_print((uint32_t)&filep_local->f_owner.lock.dep_map.class_cache,INIT_TOKEN+71);
              quasi_print((uint32_t)&filep_local->f_owner.lock.dep_map.name,INIT_TOKEN+72);
              #ifdef CONFIG_LOCK_STAT
              quasi_print((uint32_t)&filep_local->f_owner.lock.dep_map.cpu,INIT_TOKEN+73);
              quasi_print((uint32_t)&filep_local->f_owner.lock.dep_map.ip,INIT_TOKEN+74);
              #endif
          // } Back to 'struct rw_lock lock'
          #endif
      // } Back to 'struct fown_struct f_owner'
      quasi_print((uint32_t)&filep_local->f_owner.pid,INIT_TOKEN+75);
      quasi_print((uint32_t)&filep_local->f_owner.pid_type,INIT_TOKEN+76);
      quasi_print((uint32_t)&filep_local->f_owner.signum,INIT_TOKEN+77);
  // } Back to 'struct file filep_local'
  quasi_print((uint32_t)&filep_local->f_ra,INIT_TOKEN+78);
  // { Members of 'struct file_ra_state f_ra'
      quasi_print((uint32_t)&filep_local->f_ra.start,INIT_TOKEN+79);
      quasi_print((uint32_t)&filep_local->f_ra.size,INIT_TOKEN+80);
      quasi_print((uint32_t)&filep_local->f_ra.async_size,INIT_TOKEN+81);
      quasi_print((uint32_t)&filep_local->f_ra.ra_pages,INIT_TOKEN+82);
      quasi_print((uint32_t)&filep_local->f_ra.mmap_miss,INIT_TOKEN+83);
      quasi_print((uint32_t)&filep_local->f_ra.prev_pos,INIT_TOKEN+84);
  // } Back to 'struct file filep_local'
  quasi_print((uint32_t)&filep_local->f_version,INIT_TOKEN+85);
  #ifdef CONFIG_SECURITY
  quasi_print((uint32_t)&filep_local->f_security,INIT_TOKEN+86);
  #endif
  quasi_print((uint32_t)&filep_local->private_data,INIT_TOKEN+87);
  #ifdef CONFIG_EPOLL
  quasi_print((uint32_t)&filep_local->f_ep_links,INIT_TOKEN+88);
  quasi_print((uint32_t)&filep_local->f_tfile_llink,INIT_TOKEN+89);
  #endif
  quasi_print((uint32_t)&filep_local->f_mapping,INIT_TOKEN+90);
  return NULL;
}

static int __init testoffsets_init(void) 
{
  pdev_check(NULL, NULL);
  dev_check(NULL);
  file_check(NULL);
  return 0;
}

static void __exit testoffsets_exit(void){
   printk(KERN_INFO "Goodbye!\n");
}

module_init(testoffsets_init);
module_exit(testoffsets_exit);
