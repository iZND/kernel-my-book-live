/*
 * (c) Copyright 2010 Western Digital Technologies, Inc.  All Rights Reserved.
 *
 * /sys drivers for GPIO pins
 */

#include <linux/platform_device.h>
#include <linux/of_platform.h>


/*
 * resource data should be in dts file, but, for now ...
 */
static struct resource apollo3g_gpio1_resources[] = {
	[0] = {
		.start	= 0xe0000000,
		.end	= 0xe0000003,
		.flags  = IORESOURCE_MEM,
	},
};

static struct platform_device apollo3g_gpio1_device = {
        .name = "apollo3g_gpio1",
        .id = 0,
        .num_resources = ARRAY_SIZE(apollo3g_gpio1_resources),
        .resource = apollo3g_gpio1_resources,
};

static struct resource apollo3g_gpio2_resources[] = {
	[0] = {
		.start	= 0xe1000000,
		.end	= 0xe1000003,
		.flags  = IORESOURCE_MEM,
	},
};

static struct platform_device apollo3g_gpio2_device = {
        .name = "apollo3g_gpio2",
        .id = 0,
        .num_resources = ARRAY_SIZE(apollo3g_gpio2_resources),
        .resource = apollo3g_gpio2_resources,
};

static struct platform_device *apollo3g_devs[] __initdata = {
        &apollo3g_gpio1_device,
        &apollo3g_gpio2_device,
};

static const struct of_device_id apollo3g_gpio_match[] = {
	{ .compatible = "amcc,apollo3g", },
	{}
};

static struct of_platform_driver apollo3g_gpio_driver = {
	.name = "apollo3g-gpio",
};

static int __init apollo3g_gpio_init(void)
{
	printk(KERN_INFO "%s: GPIO 1 @ 0x%llx; GPIO 2 @ 0x%llx\n",
	       __FUNCTION__, apollo3g_gpio1_device.resource[0].start,
	       apollo3g_gpio2_device.resource[0].start);

	return of_register_platform_driver(&apollo3g_gpio_driver);
}
device_initcall(apollo3g_gpio_init);
