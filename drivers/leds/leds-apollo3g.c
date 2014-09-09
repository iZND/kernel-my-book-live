/*
 * LED Platform driver for Apollo3G board.
 *
 * © 2010 Western Digital Technologies, Inc. All rights reserved.
 *
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/completion.h>
#include <linux/leds.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/ioport.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <linux/suspend.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/signal.h>
#include <linux/freezer.h>



#define  _3G_BIT_LED_RED        0x10
#define  _3G_BIT_LED_GREEN      0x20
#define  _3G_BIT_LED_BLUE       0x40
#define  _3G_BIT_LED_YELLOW     (_3G_BIT_LED_GREEN | _3G_BIT_LED_RED)
#define  _3G_BIT_LED_ALL        0x70
#define  _3G_BIT_LED_OFF        0x00

#define  _3G_LED_OFF    0
#define  _3G_LED_RED    1
#define  _3G_LED_GREEN  2
#define  _3G_LED_BLUE   3
#define  _3G_LED_YELLOW 4
#define  _3G_LED_ALL    5
#define  _3G_LED_WHITE  5  /* save as _ALL */

#define  _BLINK_YES     1
#define  _BLINK_NO      0

#define  HDD_BLINK_RATE 250

static DEFINE_SPINLOCK(led_lock);
struct task_struct * threadptr;

wait_queue_head_t  ts_wait;
int blink_flag = 0;


void __iomem *led_port = NULL;

typedef struct led_state_s {
   int cur_color;
   int cur_action;
} led_state_t;

led_state_t  led_state = { .cur_color  = _3G_LED_YELLOW,
                           .cur_action = _BLINK_NO
                         };  

EXPORT_SYMBOL(led_port);

/****************************************************/
/* read value from 3g led_port */
   u8 read_3gled( void ) {
   return readb(led_port); 
}

/****************************************************/
/* read-modify-write 3g led port */
u8 write_3gled( u8 mask ,u8 value ) {
   u8 regval;

   regval = read_3gled();
   regval &= ~mask;
   regval |= (value & mask); 
   writeb( regval, led_port);
   return regval;
}

/****************************************************/
/* return 3g led color */
static enum led_brightness a3g_led_get( struct led_classdev * led_cdev ) {
   unsigned char readval;

   return led_state.cur_color;
}

/****************************************************/
/* set 3g led color */
static void a3g_led_set(struct led_classdev *led_cdev,  enum led_brightness value) {

   unsigned long flags;

   spin_lock_irqsave(&led_lock, flags);

   switch (value) {
      case _3G_LED_RED:
         write_3gled( _3G_BIT_LED_ALL, _3G_BIT_LED_RED);  
         break;
      case _3G_LED_GREEN:
         write_3gled( _3G_BIT_LED_ALL, _3G_BIT_LED_GREEN);  
         break;
      case _3G_LED_BLUE:
         write_3gled( _3G_BIT_LED_ALL, _3G_BIT_LED_BLUE);  
         break;
      case _3G_LED_OFF:
         write_3gled( _3G_BIT_LED_ALL, _3G_BIT_LED_OFF);  
         break;
      case _3G_LED_ALL:
         write_3gled( _3G_BIT_LED_ALL, _3G_BIT_LED_ALL);  
         break;
      case _3G_LED_YELLOW:
         write_3gled(_3G_BIT_LED_ALL, _3G_BIT_LED_YELLOW);  
         break;
      default:
         break; /* should never be here */
   }
   led_state.cur_color = value; 

   spin_unlock_irqrestore(&led_lock, flags);

}

/****************************************************/
/* set 3g led blinking */
static int a3g_led_blink(struct led_classdev *led_cdev,  int value) {
  
   /* 
    * if forced blink, don't set blink_flag
    */
   if( blink_flag == 2 ) {
	  return 0;
   }
  
   /*spin_lock_irqsave(&led_lock, flags);*/
   /* user wants to blink led */
   if( value == 1 ) {
      blink_flag = 1;
      wake_up(&ts_wait);
   } 
   else if( value == 0) {
      blink_flag = 0;
   }
   else if( value == 2 ) {
      blink_flag = 2;
      wake_up(&ts_wait);
   }
   // printk(KERN_DEBUG "%s: Got blink signal - input blink value %d, blink_flag %d\n", __func__, value, blink_flag);

  /* spin_unlock_irqrestore(&led_lock, flags);*/

   return 0;
}

/****************************************************/
/* 
 *   flag = blink or not
 *   color = blinking color
 */
void signal_hdd_led(int flag, int color) {
 
   /*
    *  if forced blinking was set, keep it blinking forever
    */
   if( blink_flag == 2 ) {
      return;
   }

   if( flag &&   /* blink == yes */
       (led_state.cur_color == _3G_LED_GREEN)
#if 0
       (led_state.cur_color != _3G_LED_WHITE)  && /* don't touch fw update led */
       (led_state.cur_color != _3G_LED_RED)    && /* don't touch system error led */
       !((led_state.cur_color == _3G_LED_BLUE) && (led_state.cur_action == _BLINK_YES)) && /* leave identity alone */
       (color != _3G_LED_RED)
#endif
     ) {
      if( color == _3G_LED_RED ) {
         a3g_led_set( NULL, _3G_LED_RED);         
      }
      blink_flag = 1;
      wake_up(&ts_wait);
   }
   else if( ! flag &&   /* blink == no */
	        ( led_state.cur_color == _3G_LED_GREEN ) ) 
   {
        blink_flag = 0;
   }

   //printk(KERN_DEBUG "%s: Got HDD signal - color %d, blink %d, blink_flag %d\n", __func__, color, flag, blink_flag);
}

static struct led_classdev a3g_led_dev = { 
        .name           = "a3g_led",
        .color_set      = a3g_led_set,
        .color_get      = a3g_led_get,
        .blink_set_3g   = a3g_led_blink,
};

/****************************************************/
static int __init a3g_led_probe(struct platform_device *pdev ) {

    /* Not used */
    return 0;
}

/****************************************************/
static int __devexit a3g_led_remove(struct platform_device *pdev){

    led_classdev_unregister(&a3g_led_dev);
    if( led_port ){
       iounmap(led_port);
       led_port = NULL;
    }
    return 0;
}
static struct platform_driver a3g_led_driver = {
    .probe      = a3g_led_probe, 
    .remove     = __devexit_p(a3g_led_remove),
    .driver     = {
                 .name = "a3g-leds",
                .owner = THIS_MODULE,
    },
};

#if 0
struct platform_device {
        const char      * name;
        int             id; 
        struct device   dev;
        u32             num_resources;
        struct resource * resource;

        struct platform_device_id       *id_entry;

        /* arch specific additions */
        struct pdev_archdata    archdata;
};
#endif

static struct resource a3g_res = {
                      .name = "cs1",
                      .start = 0x4e0000000ULL,
                      .end = 0x4e0000300ULL,
                      /*.flags = IORESOURCE_IO,*/
                      .flags = IORESOURCE_MEM,
                   };


/****************************************************/
static int a3g_led_blink_thread( void * data ) {
   unsigned char readval, color;

   struct task_struct * tsk = current;
   struct sched_param param = { .sched_priority = 1};
   
   init_waitqueue_head(&ts_wait);

   sched_setscheduler(tsk, SCHED_FIFO, &param);
   set_freezable();

    while( !kthread_should_stop() ) {

      led_state.cur_action = _BLINK_NO;
      /* always set current color before blinking */
      a3g_led_set( NULL, led_state.cur_color);
      wait_event_freezable_timeout(ts_wait, blink_flag || kthread_should_stop(), MAX_SCHEDULE_TIMEOUT); 
      if( led_port ) {
         readval = readb(led_port);
         color = readval & _3G_BIT_LED_ALL;
         write_3gled( _3G_BIT_LED_ALL, _3G_BIT_LED_OFF);  
         msleep(HDD_BLINK_RATE);
         write_3gled( _3G_BIT_LED_ALL, color);  
         msleep(HDD_BLINK_RATE);
         led_state.cur_action = _BLINK_YES;
      }
   }

   return 0;
}


/****************************************************/
static int __init a3g_led_init(void) {

   resource_size_t res_size;
   struct resource *phys_res = &a3g_res;
   int retval;

   res_size = resource_size(phys_res); 

   if( !request_mem_region(phys_res->start, res_size, phys_res->name) ) {
      printk(KERN_DEBUG "**** error request_mem_region()\n");
      return -1;
   }
       
   led_port = ioremap(phys_res->start, res_size);
   if (led_port == NULL) {
      release_mem_region(phys_res->start, res_size);
      printk(KERN_DEBUG "*** Error ioremap()");
      return -1;
   }
   else {
      retval = led_classdev_register(NULL, &a3g_led_dev);
      if (retval) {
         led_classdev_unregister(&a3g_led_dev);
         iounmap(led_port);
         led_port = NULL;     
         release_mem_region(phys_res->start, res_size);
         return -1;
      }

      threadptr = kthread_run( a3g_led_blink_thread, NULL, "a3gblink_t");
     
      
      return platform_driver_register(&a3g_led_driver);
   }
}

/****************************************************/
static void __exit a3g_led_exit(void) {

    platform_driver_unregister(&a3g_led_driver);
    if( led_port ){
       led_classdev_unregister(&a3g_led_dev);
       iounmap(led_port);
       led_port = NULL;
       if( threadptr ){
          kthread_stop(threadptr);
       }
       release_mem_region(a3g_res.start, (a3g_res.end - a3g_res.start + 1));
    }
}


module_init(a3g_led_init);
module_exit(a3g_led_exit);

MODULE_AUTHOR("Hai Le <hai.le@wdc.com>");
MODULE_DESCRIPTION("Apollo3G LED driver");
MODULE_LICENSE("GPL");
