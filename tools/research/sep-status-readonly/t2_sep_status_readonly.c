// SPDX-License-Identifier: GPL-2.0-only
/* Fixed status registers only. No FIFO reads, MMIO writes, DMA or rebinding. */
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/dmi.h>
#include <linux/dma-mapping.h>

/* Exact prefix shared by the two pinned startup trials; checked by srcversion. */
struct t2_sep_prefix {
	struct pci_dev *pdev;
	void __iomem *bar;
	void *ool_in;
	dma_addr_t ool_in_dma;
	void *ool_out;
	dma_addr_t ool_out_dma;
	bool ool_in_registered;
	bool ool_out_registered;
	void *acm_ool_in;
	dma_addr_t acm_ool_in_dma;
	void *acm_ool_out;
	dma_addr_t acm_ool_out_dma;
	bool acm_ool_in_registered;
	bool acm_ool_out_registered;
};

static int __init t2_sep_status_init(void)
{
	struct pci_dev *pdev;
	void __iomem *bar;
	int ret = -ENODEV;

	if (!dmi_match(DMI_PRODUCT_NAME, "MacBookPro16,1"))
		return -ENODEV;
	pdev = pci_get_domain_bus_and_slot(0, 4, PCI_DEVFN(0, 2));
	if (!pdev)
		return -ENODEV;
	device_lock(&pdev->dev);
	if (pdev->vendor != 0x106b || pdev->device != 0x1802 ||
	    !pdev->dev.driver ||
	    strcmp(pdev->dev.driver->name, "t2_sep_transport") ||
	    pdev->current_state != PCI_D0 ||
	    !(pci_resource_flags(pdev, 4) & IORESOURCE_MEM) ||
	    pci_resource_len(pdev, 4) < 0x804c)
		goto out;
	bar = pci_iomap(pdev, 4, 0);
	if (!bar) {
		ret = -ENOMEM;
		goto out;
	}
	pr_info("t2_sep_status_readonly: inbox=%#x outbox=%#x control=%#x reset=%#x start=%#x\n",
		readl(bar + 0x108), readl(bar + 0x10c),
		readl(bar + 0x8028), readl(bar + 0x8040),
		readl(bar + 0x8048));
	pci_iounmap(pdev, bar);
	if (pdev->dev.driver->owner && pdev->dev.driver->owner->srcversion &&
	    (!strcmp(pdev->dev.driver->owner->srcversion, "C3E877B6001A0109956ED9C") ||
	     !strcmp(pdev->dev.driver->owner->srcversion, "509B887928226059FBC3264"))) {
		const struct t2_sep_prefix *sep = pci_get_drvdata(pdev);

		if (sep && sep->pdev == pdev)
			pr_info("t2_sep_status_readonly: DMA above32 aks_in=%u aks_out=%u acm_in=%u acm_out=%u registered=%u%u%u%u\n",
				!!(sep->ool_in_dma >> 32), !!(sep->ool_out_dma >> 32),
				!!(sep->acm_ool_in_dma >> 32), !!(sep->acm_ool_out_dma >> 32),
				sep->ool_in_registered, sep->ool_out_registered,
				sep->acm_ool_in_registered, sep->acm_ool_out_registered);
	}
	ret = 0;
out:
	device_unlock(&pdev->dev);
	pci_dev_put(pdev);
	return ret;
}

static void __exit t2_sep_status_exit(void) {}
module_init(t2_sep_status_init);
module_exit(t2_sep_status_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("One-shot fixed-register T2 SEP status observation");
