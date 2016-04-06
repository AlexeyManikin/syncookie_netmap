#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x366c239a, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xde1fc7a3, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0x2d3385d3, __VMLINUX_SYMBOL_STR(system_wq) },
	{ 0xb3ebd2d2, __VMLINUX_SYMBOL_STR(device_remove_file) },
	{ 0x53d7a445, __VMLINUX_SYMBOL_STR(netdev_info) },
	{ 0x399033ef, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xb95f5dce, __VMLINUX_SYMBOL_STR(pci_bus_read_config_byte) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xdecf8242, __VMLINUX_SYMBOL_STR(ethtool_op_get_ts_info) },
	{ 0xe4689576, __VMLINUX_SYMBOL_STR(ktime_get_with_offset) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x99840d00, __VMLINUX_SYMBOL_STR(timecounter_init) },
	{ 0xab897d6, __VMLINUX_SYMBOL_STR(dcb_ieee_setapp) },
	{ 0x8f0ee712, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0x619cb7dd, __VMLINUX_SYMBOL_STR(simple_read_from_buffer) },
	{ 0x58bf14b1, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0x6bf1c17f, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0x98b2158c, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0xefc08ee8, __VMLINUX_SYMBOL_STR(dcb_ieee_delapp) },
	{ 0xcc84229b, __VMLINUX_SYMBOL_STR(napi_disable) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0xb87eb8d, __VMLINUX_SYMBOL_STR(pci_sriov_set_totalvfs) },
	{ 0xccfe49dd, __VMLINUX_SYMBOL_STR(__napi_schedule_irqoff) },
	{ 0x197220f3, __VMLINUX_SYMBOL_STR(skb_pad) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x9469482, __VMLINUX_SYMBOL_STR(kfree_call_rcu) },
	{ 0xb1acc4c, __VMLINUX_SYMBOL_STR(napi_gro_flush) },
	{ 0xbd100793, __VMLINUX_SYMBOL_STR(cpu_online_mask) },
	{ 0x77ec9137, __VMLINUX_SYMBOL_STR(napi_hash_del) },
	{ 0xff8c5b9c, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0xc7a4fbed, __VMLINUX_SYMBOL_STR(rtnl_lock) },
	{ 0x9c5995d3, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x51fff130, __VMLINUX_SYMBOL_STR(hwmon_device_unregister) },
	{ 0x4ea25709, __VMLINUX_SYMBOL_STR(dql_reset) },
	{ 0x583a555d, __VMLINUX_SYMBOL_STR(netif_carrier_on) },
	{ 0xd9d3bcd3, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0xc2a034f2, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0x58c50b29, __VMLINUX_SYMBOL_STR(netif_carrier_off) },
	{ 0x88bfa7e, __VMLINUX_SYMBOL_STR(cancel_work_sync) },
	{ 0x3fec048f, __VMLINUX_SYMBOL_STR(sg_next) },
	{ 0x949f7342, __VMLINUX_SYMBOL_STR(__alloc_percpu) },
	{ 0x88874619, __VMLINUX_SYMBOL_STR(driver_for_each_device) },
	{ 0x65443787, __VMLINUX_SYMBOL_STR(__dev_kfree_skb_any) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0x9580deb, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0xd02e6a3d, __VMLINUX_SYMBOL_STR(pci_bus_write_config_word) },
	{ 0x7321a5df, __VMLINUX_SYMBOL_STR(debugfs_create_file) },
	{ 0x4629334c, __VMLINUX_SYMBOL_STR(__preempt_count) },
	{ 0xb5aa7165, __VMLINUX_SYMBOL_STR(dma_pool_destroy) },
	{ 0x7a2af7b4, __VMLINUX_SYMBOL_STR(cpu_number) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x62cff4ff, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0xf4c91ed, __VMLINUX_SYMBOL_STR(ns_to_timespec) },
	{ 0xf85a2564, __VMLINUX_SYMBOL_STR(pci_dev_driver) },
	{ 0x9041fd19, __VMLINUX_SYMBOL_STR(netif_napi_del) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xc9ec4e21, __VMLINUX_SYMBOL_STR(free_percpu) },
	{ 0x733c3b54, __VMLINUX_SYMBOL_STR(kasprintf) },
	{ 0x3aad87bb, __VMLINUX_SYMBOL_STR(__netdev_alloc_skb) },
	{ 0x27c33efe, __VMLINUX_SYMBOL_STR(csum_ipv6_magic) },
	{ 0x19bf9b9c, __VMLINUX_SYMBOL_STR(__pskb_pull_tail) },
	{ 0xb74b7afb, __VMLINUX_SYMBOL_STR(ptp_clock_unregister) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xfe7c4287, __VMLINUX_SYMBOL_STR(nr_cpu_ids) },
	{ 0xaed53651, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x990bf0f5, __VMLINUX_SYMBOL_STR(dca3_get_tag) },
	{ 0xbd288adc, __VMLINUX_SYMBOL_STR(netif_schedule_queue) },
	{ 0x13f58d7f, __VMLINUX_SYMBOL_STR(ptp_clock_event) },
	{ 0x706d051c, __VMLINUX_SYMBOL_STR(del_timer_sync) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x5588e945, __VMLINUX_SYMBOL_STR(dcb_getapp) },
	{ 0x4ffcf2c1, __VMLINUX_SYMBOL_STR(dcb_setapp) },
	{ 0x5ad96637, __VMLINUX_SYMBOL_STR(pci_enable_pcie_error_reporting) },
	{ 0xac34ecec, __VMLINUX_SYMBOL_STR(dca_register_notify) },
	{ 0x6df0fa19, __VMLINUX_SYMBOL_STR(netif_tx_wake_queue) },
	{ 0x828af37f, __VMLINUX_SYMBOL_STR(pci_restore_state) },
	{ 0x49c2289d, __VMLINUX_SYMBOL_STR(netif_tx_stop_all_queues) },
	{ 0x1a33ab9, __VMLINUX_SYMBOL_STR(dca_unregister_notify) },
	{ 0xbb84a737, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x1916e38c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0xc354bac9, __VMLINUX_SYMBOL_STR(dev_addr_del) },
	{ 0xec567b44, __VMLINUX_SYMBOL_STR(netif_set_xps_queue) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x69a2972b, __VMLINUX_SYMBOL_STR(ethtool_op_get_link) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x3c3fce39, __VMLINUX_SYMBOL_STR(__local_bh_enable_ip) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xa00aca2a, __VMLINUX_SYMBOL_STR(dql_completed) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xcd279169, __VMLINUX_SYMBOL_STR(nla_find) },
	{ 0xdc59fc2d, __VMLINUX_SYMBOL_STR(vxlan_get_rx_port) },
	{ 0x1609cf38, __VMLINUX_SYMBOL_STR(free_netdev) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x3210ae82, __VMLINUX_SYMBOL_STR(register_netdev) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0x93515554, __VMLINUX_SYMBOL_STR(dev_close) },
	{ 0x5379c761, __VMLINUX_SYMBOL_STR(netif_set_real_num_rx_queues) },
	{ 0x16e5c2a, __VMLINUX_SYMBOL_STR(mod_timer) },
	{ 0x61bf8cd8, __VMLINUX_SYMBOL_STR(netif_set_real_num_tx_queues) },
	{ 0x6df301b8, __VMLINUX_SYMBOL_STR(netif_napi_add) },
	{ 0x2a37d074, __VMLINUX_SYMBOL_STR(dma_pool_free) },
	{ 0xdd938346, __VMLINUX_SYMBOL_STR(dcb_ieee_getapp_mask) },
	{ 0xf4ada60f, __VMLINUX_SYMBOL_STR(ptp_clock_register) },
	{ 0x2072ee9b, __VMLINUX_SYMBOL_STR(request_threaded_irq) },
	{ 0x1d5d2e00, __VMLINUX_SYMBOL_STR(dca_add_requester) },
	{ 0xf8af1b48, __VMLINUX_SYMBOL_STR(skb_pull) },
	{ 0x4e8f013, __VMLINUX_SYMBOL_STR(simple_open) },
	{ 0x5d74e660, __VMLINUX_SYMBOL_STR(dev_open) },
	{ 0xe523ad75, __VMLINUX_SYMBOL_STR(synchronize_irq) },
	{ 0xc542933a, __VMLINUX_SYMBOL_STR(timecounter_read) },
	{ 0xc6235226, __VMLINUX_SYMBOL_STR(pci_find_capability) },
	{ 0xb975ee58, __VMLINUX_SYMBOL_STR(device_create_file) },
	{ 0x44c703b0, __VMLINUX_SYMBOL_STR(arch_dma_alloc_attrs) },
	{ 0xc911b9d5, __VMLINUX_SYMBOL_STR(eth_get_headlen) },
	{ 0x29960dd9, __VMLINUX_SYMBOL_STR(pci_select_bars) },
	{ 0xbb73d3aa, __VMLINUX_SYMBOL_STR(netif_receive_skb_sk) },
	{ 0xa8b76a68, __VMLINUX_SYMBOL_STR(timecounter_cyc2time) },
	{ 0x6660f4d6, __VMLINUX_SYMBOL_STR(netif_device_attach) },
	{ 0xe641a982, __VMLINUX_SYMBOL_STR(napi_gro_receive) },
	{ 0xc6107661, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0x40a9b349, __VMLINUX_SYMBOL_STR(vzalloc) },
	{ 0x78764f4e, __VMLINUX_SYMBOL_STR(pv_irq_ops) },
	{ 0xe3000e38, __VMLINUX_SYMBOL_STR(dev_addr_add) },
	{ 0x7487e1ce, __VMLINUX_SYMBOL_STR(__free_pages) },
	{ 0xb2ea4ca8, __VMLINUX_SYMBOL_STR(pci_disable_link_state) },
	{ 0x618911fc, __VMLINUX_SYMBOL_STR(numa_node) },
	{ 0x3a5eacc2, __VMLINUX_SYMBOL_STR(netif_device_detach) },
	{ 0xbdbd6813, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0x12a38747, __VMLINUX_SYMBOL_STR(usleep_range) },
	{ 0xb421d688, __VMLINUX_SYMBOL_STR(pci_enable_msix_range) },
	{ 0xb1f9f52f, __VMLINUX_SYMBOL_STR(pci_bus_read_config_word) },
	{ 0x860e338f, __VMLINUX_SYMBOL_STR(pci_bus_read_config_dword) },
	{ 0xbba70a2d, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0x7a9e417a, __VMLINUX_SYMBOL_STR(pci_cleanup_aer_uncorrect_error_status) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xb9249d16, __VMLINUX_SYMBOL_STR(cpu_possible_mask) },
	{ 0x52e107bf, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x89e89caf, __VMLINUX_SYMBOL_STR(napi_hash_add) },
	{ 0x74b2576a, __VMLINUX_SYMBOL_STR(ndo_dflt_fdb_add) },
	{ 0xdc81668d, __VMLINUX_SYMBOL_STR(napi_complete_done) },
	{ 0xcda5bbbe, __VMLINUX_SYMBOL_STR(eth_type_trans) },
	{ 0x771cf835, __VMLINUX_SYMBOL_STR(dma_pool_alloc) },
	{ 0xff809e93, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x7495abf7, __VMLINUX_SYMBOL_STR(netdev_err) },
	{ 0x98001206, __VMLINUX_SYMBOL_STR(netdev_features_change) },
	{ 0xdfcc83a9, __VMLINUX_SYMBOL_STR(pci_enable_msi_range) },
	{ 0x6baff8fe, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0xcc5005fe, __VMLINUX_SYMBOL_STR(msleep_interruptible) },
	{ 0x52468a6a, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x3928efe9, __VMLINUX_SYMBOL_STR(__per_cpu_offset) },
	{ 0x680ec266, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xf6ebc03b, __VMLINUX_SYMBOL_STR(net_ratelimit) },
	{ 0xf61b03a, __VMLINUX_SYMBOL_STR(pci_set_power_state) },
	{ 0x19805b14, __VMLINUX_SYMBOL_STR(netdev_warn) },
	{ 0xbb4f4766, __VMLINUX_SYMBOL_STR(simple_write_to_buffer) },
	{ 0x75f6aa6e, __VMLINUX_SYMBOL_STR(eth_validate_addr) },
	{ 0x1390cca6, __VMLINUX_SYMBOL_STR(pci_disable_pcie_error_reporting) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x277818a1, __VMLINUX_SYMBOL_STR(___pskb_trim) },
	{ 0xf4b4183b, __VMLINUX_SYMBOL_STR(param_array_ops) },
	{ 0x4601ad6f, __VMLINUX_SYMBOL_STR(ptp_clock_index) },
	{ 0x92959b75, __VMLINUX_SYMBOL_STR(pci_disable_msi) },
	{ 0x4fb0b9c6, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0xb94e6ec7, __VMLINUX_SYMBOL_STR(skb_add_rx_frag) },
	{ 0x3b67936e, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0xfea687dc, __VMLINUX_SYMBOL_STR(pci_prepare_to_sleep) },
	{ 0xed2afff6, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xa8721b97, __VMLINUX_SYMBOL_STR(system_state) },
	{ 0xb352177e, __VMLINUX_SYMBOL_STR(find_first_bit) },
	{ 0xe578478b, __VMLINUX_SYMBOL_STR(pci_get_device) },
	{ 0x63c4d61f, __VMLINUX_SYMBOL_STR(__bitmap_weight) },
	{ 0x82ba7e70, __VMLINUX_SYMBOL_STR(dev_warn) },
	{ 0x71d2abd0, __VMLINUX_SYMBOL_STR(unregister_netdev) },
	{ 0x2b691561, __VMLINUX_SYMBOL_STR(ndo_dflt_bridge_getlink) },
	{ 0x55f5019b, __VMLINUX_SYMBOL_STR(__kmalloc_node) },
	{ 0xca5ae169, __VMLINUX_SYMBOL_STR(pci_dev_put) },
	{ 0x3adb20fb, __VMLINUX_SYMBOL_STR(netif_wake_subqueue) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0x6ad93059, __VMLINUX_SYMBOL_STR(pci_vfs_assigned) },
	{ 0x9e0c711d, __VMLINUX_SYMBOL_STR(vzalloc_node) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0xf3a743a3, __VMLINUX_SYMBOL_STR(consume_skb) },
	{ 0xeceb2fbf, __VMLINUX_SYMBOL_STR(dca_remove_requester) },
	{ 0x3d7bee7d, __VMLINUX_SYMBOL_STR(pci_enable_device_mem) },
	{ 0xef660544, __VMLINUX_SYMBOL_STR(skb_tstamp_tx) },
	{ 0xb78d0f2b, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xd64ee2a0, __VMLINUX_SYMBOL_STR(pci_wake_from_d3) },
	{ 0x3c1e054c, __VMLINUX_SYMBOL_STR(pci_release_selected_regions) },
	{ 0xc34a1eec, __VMLINUX_SYMBOL_STR(pci_request_selected_regions) },
	{ 0xbb128381, __VMLINUX_SYMBOL_STR(irq_set_affinity_hint) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xa9856a20, __VMLINUX_SYMBOL_STR(dma_pool_create) },
	{ 0xbc3edc64, __VMLINUX_SYMBOL_STR(skb_copy_bits) },
	{ 0x676ed428, __VMLINUX_SYMBOL_STR(hwmon_device_register) },
	{ 0xd1f8af2d, __VMLINUX_SYMBOL_STR(pci_find_ext_capability) },
	{ 0x6e720ff2, __VMLINUX_SYMBOL_STR(rtnl_unlock) },
	{ 0x9e7d6bd0, __VMLINUX_SYMBOL_STR(__udelay) },
	{ 0xd175cbda, __VMLINUX_SYMBOL_STR(dma_ops) },
	{ 0x880f0e74, __VMLINUX_SYMBOL_STR(pcie_get_minimum_link) },
	{ 0x4c118a00, __VMLINUX_SYMBOL_STR(pcie_capability_read_word) },
	{ 0xd3b30b15, __VMLINUX_SYMBOL_STR(device_set_wakeup_enable) },
	{ 0xf20dabd8, __VMLINUX_SYMBOL_STR(free_irq) },
	{ 0x2a3c6d8f, __VMLINUX_SYMBOL_STR(pci_save_state) },
	{ 0x96bf92e8, __VMLINUX_SYMBOL_STR(alloc_etherdev_mqs) },
	{ 0x7f4b1d77, __VMLINUX_SYMBOL_STR(netdev_crit) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ptp,dca,vxlan";

MODULE_ALIAS("pci:v00008086d000010B6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C6sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010C8sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000150Bsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DDsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010ECsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F1sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010E1sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F4sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010DBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001508sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F7sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010FCsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001517sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010FBsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001507sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001514sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F9sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000152Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001529sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000151Csv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000010F8sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001528sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000154Dsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000154Fsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001557sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d0000154Asv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001558sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001560sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d00001563sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015D1sv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015AAsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015ABsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015ACsv*sd*bc*sc*i*");
MODULE_ALIAS("pci:v00008086d000015ADsv*sd*bc*sc*i*");

MODULE_INFO(srcversion, "6080343B3D384C837131774");
