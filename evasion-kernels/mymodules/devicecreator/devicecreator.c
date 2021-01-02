#include <linux/init.h>          
#include <linux/module.h>        
#include <linux/device.h>        
#include <linux/kernel.h>        
#include <linux/fs.h>            
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include <asm/uaccess.h>         

#define  SELF_DEVICE_NAME "devicecreator"   
#define  SELF_CLASS_NAME  "dcreator"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ivanp");
MODULE_DESCRIPTION("A driver to create platoform devices");
MODULE_VERSION("0.1");

char funcprotos[] __attribute__((section("protos"))) = "\x00";

static int    majorNumber;
static struct class*  selfClass  = NULL;
static struct device* selfDevice = NULL;

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);


/*** AVAILABLE DEVICES BEGIN **/
/* Below are devices the driver is able to create.  In order to add a new
 * device you need to provide the corresponding 'platform_device' structure,
 * and define its fields. The best way to do it is to extract them from msm
 * kernel source */

/*
 * msm_vidc begin
 */

struct msm_bus_vectors {
	int src; /* Master */
	int dst; /* Slave */
	uint64_t ab; /* Arbitrated bandwidth */
	uint64_t ib; /* Instantaneous bandwidth */
};

struct msm_bus_paths {
	int num_paths;
	struct msm_bus_vectors *vectors;
};

struct msm_bus_scale_pdata {
	struct msm_bus_paths *usecase;
	int num_usecases;
	const char *name;
	/*
	 * If the active_only flag is set to 1, the BW request is applied
	 * only when at least one CPU is active (powered on). If the flag
	 * is set to 0, then the BW request is always applied irrespective
	 * of the CPU state.
	 */
	unsigned int active_only;
};


struct msm_vidc_platform_data {
	int memtype;
	u32 enable_ion;
	int disable_dmx;
	int disable_fullhd;
	u32 cp_enabled;
	u32 secure_wb_heap;
	u32 enable_sec_metadata;
//#ifdef CONFIG_MSM_BUS_SCALING
	struct msm_bus_scale_pdata *vidc_bus_client_pdata;
//#endif
	int cont_mode_dpb_count;
	int disable_turbo;
	unsigned long fw_addr;
};

enum ion_heap_ids {
	INVALID_HEAP_ID = -1,
	ION_CP_MM_HEAP_ID = 8,
	ION_CP_MFC_HEAP_ID = 12,
	ION_CP_WB_HEAP_ID = 16, /* 8660 only */
	ION_CAMERA_HEAP_ID = 20, /* 8660 only */
	ION_SYSTEM_CONTIG_HEAP_ID = 21,
	ION_ADSP_HEAP_ID = 22,
	ION_SF_HEAP_ID = 24,
	ION_IOMMU_HEAP_ID = 25,
	ION_QSECOM_HEAP_ID = 27,
	ION_AUDIO_HEAP_ID = 28,

	ION_MM_FIRMWARE_HEAP_ID = 29,
	ION_SYSTEM_HEAP_ID = 30,

	ION_HEAP_ID_RESERVED = 31 /** Bit reserved for ION_SECURE flag */
};

#define MSM_VIDC_BASE_PHYS 0x04400000
#define MSM_VIDC_BASE_SIZE 0x00100000
#define GIC_SPI_START 32
#define VCODEC_IRQ				(GIC_SPI_START + 49)


#define IORESOURCE_MEM		0x00000200
#define ROT_IRQ					(GIC_SPI_START + 73)
#define IORESOURCE_IRQ		0x00000400
#define FABRIC_ID_KEY 1024
#define SLAVE_ID_KEY ((FABRIC_ID_KEY) >> 1)
enum msm_bus_fabric_slave_type {
	MSM_BUS_SLAVE_FIRST = SLAVE_ID_KEY,
	MSM_BUS_SLAVE_EBI_CH0 = SLAVE_ID_KEY,
	MSM_BUS_SLAVE_EBI_CH1,
	MSM_BUS_SLAVE_AMPSS_L2,
	MSM_BUS_APPSS_SLAVE_FAB_MMSS,
	MSM_BUS_APPSS_SLAVE_FAB_SYSTEM,

	MSM_BUS_SYSTEM_SLAVE_FAB_APPS,
	MSM_BUS_SLAVE_SPS,
	MSM_BUS_SLAVE_SYSTEM_IMEM,
	MSM_BUS_SLAVE_AMPSS,
	MSM_BUS_SLAVE_MSS,
	MSM_BUS_SLAVE_LPASS,
	MSM_BUS_SYSTEM_SLAVE_CPSS_FPB,
	MSM_BUS_SYSTEM_SLAVE_SYSTEM_FPB,
	MSM_BUS_SYSTEM_SLAVE_MMSS_FPB,
	MSM_BUS_SLAVE_CORESIGHT,
	MSM_BUS_SLAVE_RIVA,

	MSM_BUS_SLAVE_SMI,
	MSM_BUS_MMSS_SLAVE_FAB_APPS,
	MSM_BUS_MMSS_SLAVE_FAB_APPS_1,
	MSM_BUS_SLAVE_MM_IMEM,
	MSM_BUS_SLAVE_CRYPTO,

	MSM_BUS_SLAVE_SPDM,
	MSM_BUS_SLAVE_RPM,
	MSM_BUS_SLAVE_RPM_MSG_RAM,
	MSM_BUS_SLAVE_MPM,
	MSM_BUS_SLAVE_PMIC1_SSBI1_A,
	MSM_BUS_SLAVE_PMIC1_SSBI1_B,
	MSM_BUS_SLAVE_PMIC1_SSBI1_C,
	MSM_BUS_SLAVE_PMIC2_SSBI2_A,
	MSM_BUS_SLAVE_PMIC2_SSBI2_B,

	MSM_BUS_SLAVE_GSBI1_UART,
	MSM_BUS_SLAVE_GSBI2_UART,
	MSM_BUS_SLAVE_GSBI3_UART,
	MSM_BUS_SLAVE_GSBI4_UART,
	MSM_BUS_SLAVE_GSBI5_UART,
	MSM_BUS_SLAVE_GSBI6_UART,
	MSM_BUS_SLAVE_GSBI7_UART,
	MSM_BUS_SLAVE_GSBI8_UART,
	MSM_BUS_SLAVE_GSBI9_UART,
	MSM_BUS_SLAVE_GSBI10_UART,
	MSM_BUS_SLAVE_GSBI11_UART,
	MSM_BUS_SLAVE_GSBI12_UART,
	MSM_BUS_SLAVE_GSBI1_QUP,
	MSM_BUS_SLAVE_GSBI2_QUP,
	MSM_BUS_SLAVE_GSBI3_QUP,
	MSM_BUS_SLAVE_GSBI4_QUP,
	MSM_BUS_SLAVE_GSBI5_QUP,
	MSM_BUS_SLAVE_GSBI6_QUP,
	MSM_BUS_SLAVE_GSBI7_QUP,
	MSM_BUS_SLAVE_GSBI8_QUP,
	MSM_BUS_SLAVE_GSBI9_QUP,
	MSM_BUS_SLAVE_GSBI10_QUP,
	MSM_BUS_SLAVE_GSBI11_QUP,
	MSM_BUS_SLAVE_GSBI12_QUP,
	MSM_BUS_SLAVE_EBI2_NAND,
	MSM_BUS_SLAVE_EBI2_CS0,
	MSM_BUS_SLAVE_EBI2_CS1,
	MSM_BUS_SLAVE_EBI2_CS2,
	MSM_BUS_SLAVE_EBI2_CS3,
	MSM_BUS_SLAVE_EBI2_CS4,
	MSM_BUS_SLAVE_EBI2_CS5,
	MSM_BUS_SLAVE_USB_FS1,
	MSM_BUS_SLAVE_USB_FS2,
	MSM_BUS_SLAVE_TSIF,
	MSM_BUS_SLAVE_MSM_TSSC,
	MSM_BUS_SLAVE_MSM_PDM,
	MSM_BUS_SLAVE_MSM_DIMEM,
	MSM_BUS_SLAVE_MSM_TCSR,
	MSM_BUS_SLAVE_MSM_PRNG,
	MSM_BUS_SLAVE_GSS,
	MSM_BUS_SLAVE_SATA,

	MSM_BUS_SLAVE_USB3,
	MSM_BUS_SLAVE_WCSS,
	MSM_BUS_SLAVE_OCIMEM,
	MSM_BUS_SLAVE_SNOC_OCMEM,
	MSM_BUS_SLAVE_SERVICE_SNOC,
	MSM_BUS_SLAVE_QDSS_STM,

	MSM_BUS_SLAVE_CAMERA_CFG,
	MSM_BUS_SLAVE_DISPLAY_CFG,
	MSM_BUS_SLAVE_OCMEM_CFG,
	MSM_BUS_SLAVE_CPR_CFG,
	MSM_BUS_SLAVE_CPR_XPU_CFG,
	MSM_BUS_SLAVE_MISC_CFG,
	MSM_BUS_SLAVE_MISC_XPU_CFG,
	MSM_BUS_SLAVE_VENUS_CFG,
	MSM_BUS_SLAVE_MISC_VENUS_CFG,
	MSM_BUS_SLAVE_GRAPHICS_3D_CFG,
	MSM_BUS_SLAVE_MMSS_CLK_CFG,
	MSM_BUS_SLAVE_MMSS_CLK_XPU_CFG,
	MSM_BUS_SLAVE_MNOC_MPU_CFG,
	MSM_BUS_SLAVE_ONOC_MPU_CFG,
	MSM_BUS_SLAVE_SERVICE_MNOC,

	MSM_BUS_SLAVE_OCMEM,
	MSM_BUS_SLAVE_SERVICE_ONOC,

	MSM_BUS_SLAVE_SDCC_1,
	MSM_BUS_SLAVE_SDCC_3,
	MSM_BUS_SLAVE_SDCC_2,
	MSM_BUS_SLAVE_SDCC_4,
	MSM_BUS_SLAVE_BAM_DMA,
	MSM_BUS_SLAVE_BLSP_2,
	MSM_BUS_SLAVE_USB_HSIC,
	MSM_BUS_SLAVE_BLSP_1,
	MSM_BUS_SLAVE_USB_HS,
	MSM_BUS_SLAVE_PDM,
	MSM_BUS_SLAVE_PERIPH_APU_CFG,
	MSM_BUS_SLAVE_PNOC_MPU_CFG,
	MSM_BUS_SLAVE_PRNG,
	MSM_BUS_SLAVE_SERVICE_PNOC,

	MSM_BUS_SLAVE_CLK_CTL,
	MSM_BUS_SLAVE_CNOC_MSS,
	MSM_BUS_SLAVE_SECURITY,
	MSM_BUS_SLAVE_TCSR,
	MSM_BUS_SLAVE_TLMM,
	MSM_BUS_SLAVE_CRYPTO_0_CFG,
	MSM_BUS_SLAVE_CRYPTO_1_CFG,
	MSM_BUS_SLAVE_IMEM_CFG,
	MSM_BUS_SLAVE_MESSAGE_RAM,
	MSM_BUS_SLAVE_BIMC_CFG,
	MSM_BUS_SLAVE_BOOT_ROM,
	MSM_BUS_SLAVE_CNOC_MNOC_MMSS_CFG,
	MSM_BUS_SLAVE_PMIC_ARB,
	MSM_BUS_SLAVE_SPDM_WRAPPER,
	MSM_BUS_SLAVE_DEHR_CFG,
	MSM_BUS_SLAVE_QDSS_CFG,
	MSM_BUS_SLAVE_RBCPR_CFG,
	MSM_BUS_SLAVE_RBCPR_QDSS_APU_CFG,
	MSM_BUS_SLAVE_SNOC_MPU_CFG,
	MSM_BUS_SLAVE_CNOC_ONOC_CFG,
	MSM_BUS_SLAVE_CNOC_MNOC_CFG,
	MSM_BUS_SLAVE_PNOC_CFG,
	MSM_BUS_SLAVE_SNOC_CFG,
	MSM_BUS_SLAVE_EBI1_DLL_CFG,
	MSM_BUS_SLAVE_PHY_APU_CFG,
	MSM_BUS_SLAVE_EBI1_PHY_CFG,
	MSM_BUS_SLAVE_SERVICE_CNOC,
	MSM_BUS_SLAVE_IPS_CFG,
	MSM_BUS_SLAVE_QPIC,
	MSM_BUS_SLAVE_DSI_CFG,

	MSM_BUS_SLAVE_LAST,

	MSM_BUS_SYSTEM_FPB_SLAVE_SYSTEM =
		MSM_BUS_SYSTEM_SLAVE_SYSTEM_FPB,
	MSM_BUS_CPSS_FPB_SLAVE_SYSTEM =
		MSM_BUS_SYSTEM_SLAVE_CPSS_FPB,
};
enum msm_bus_fabric_master_type {
	MSM_BUS_MASTER_FIRST = 1,
	MSM_BUS_MASTER_AMPSS_M0 = 1,
	MSM_BUS_MASTER_AMPSS_M1,
	MSM_BUS_APPSS_MASTER_FAB_MMSS,
	MSM_BUS_APPSS_MASTER_FAB_SYSTEM,

	MSM_BUS_SYSTEM_MASTER_FAB_APPSS,
	MSM_BUS_MASTER_SPS,
	MSM_BUS_MASTER_ADM_PORT0,
	MSM_BUS_MASTER_ADM_PORT1,
	MSM_BUS_SYSTEM_MASTER_ADM1_PORT0,
	MSM_BUS_MASTER_ADM1_PORT1,
	MSM_BUS_MASTER_LPASS_PROC,
	MSM_BUS_MASTER_MSS_PROCI,
	MSM_BUS_MASTER_MSS_PROCD,
	MSM_BUS_MASTER_MSS_MDM_PORT0,
	MSM_BUS_MASTER_LPASS,
	MSM_BUS_SYSTEM_MASTER_CPSS_FPB,
	MSM_BUS_SYSTEM_MASTER_SYSTEM_FPB,
	MSM_BUS_SYSTEM_MASTER_MMSS_FPB,
	MSM_BUS_MASTER_ADM1_CI,
	MSM_BUS_MASTER_ADM0_CI,
	MSM_BUS_MASTER_MSS_MDM_PORT1,

	MSM_BUS_MASTER_MDP_PORT0,
	MSM_BUS_MASTER_MDP_PORT1,
	MSM_BUS_MMSS_MASTER_ADM1_PORT0,
	MSM_BUS_MASTER_ROTATOR,
	MSM_BUS_MASTER_GRAPHICS_3D,
	MSM_BUS_MASTER_JPEG_DEC,
	MSM_BUS_MASTER_GRAPHICS_2D_CORE0,
	MSM_BUS_MASTER_VFE,
	MSM_BUS_MASTER_VPE,
	MSM_BUS_MASTER_JPEG_ENC,
	MSM_BUS_MASTER_GRAPHICS_2D_CORE1,
	MSM_BUS_MMSS_MASTER_APPS_FAB,
	MSM_BUS_MASTER_HD_CODEC_PORT0,
	MSM_BUS_MASTER_HD_CODEC_PORT1,

	MSM_BUS_MASTER_SPDM,
	MSM_BUS_MASTER_RPM,

	MSM_BUS_MASTER_MSS,
	MSM_BUS_MASTER_RIVA,
	MSM_BUS_SYSTEM_MASTER_UNUSED_6,
	MSM_BUS_MASTER_MSS_SW_PROC,
	MSM_BUS_MASTER_MSS_FW_PROC,
	MSM_BUS_MMSS_MASTER_UNUSED_2,
	MSM_BUS_MASTER_GSS_NAV,
	MSM_BUS_MASTER_PCIE,
	MSM_BUS_MASTER_SATA,
	MSM_BUS_MASTER_CRYPTO,

	MSM_BUS_MASTER_VIDEO_CAP,
	MSM_BUS_MASTER_GRAPHICS_3D_PORT1,
	MSM_BUS_MASTER_VIDEO_ENC,
	MSM_BUS_MASTER_VIDEO_DEC,

	MSM_BUS_MASTER_LPASS_AHB,
	MSM_BUS_MASTER_QDSS_BAM,
	MSM_BUS_MASTER_SNOC_CFG,
	MSM_BUS_MASTER_CRYPTO_CORE0,
	MSM_BUS_MASTER_CRYPTO_CORE1,
	MSM_BUS_MASTER_MSS_NAV,
	MSM_BUS_MASTER_OCMEM_DMA,
	MSM_BUS_MASTER_WCSS,
	MSM_BUS_MASTER_QDSS_ETR,
	MSM_BUS_MASTER_USB3,

	MSM_BUS_MASTER_JPEG,
	MSM_BUS_MASTER_VIDEO_P0,
	MSM_BUS_MASTER_VIDEO_P1,

	MSM_BUS_MASTER_MSS_PROC,
	MSM_BUS_MASTER_JPEG_OCMEM,
	MSM_BUS_MASTER_MDP_OCMEM,
	MSM_BUS_MASTER_VIDEO_P0_OCMEM,
	MSM_BUS_MASTER_VIDEO_P1_OCMEM,
	MSM_BUS_MASTER_VFE_OCMEM,
	MSM_BUS_MASTER_CNOC_ONOC_CFG,
	MSM_BUS_MASTER_RPM_INST,
	MSM_BUS_MASTER_RPM_DATA,
	MSM_BUS_MASTER_RPM_SYS,
	MSM_BUS_MASTER_DEHR,
	MSM_BUS_MASTER_QDSS_DAP,
	MSM_BUS_MASTER_TIC,

	MSM_BUS_MASTER_SDCC_1,
	MSM_BUS_MASTER_SDCC_3,
	MSM_BUS_MASTER_SDCC_4,
	MSM_BUS_MASTER_SDCC_2,
	MSM_BUS_MASTER_TSIF,
	MSM_BUS_MASTER_BAM_DMA,
	MSM_BUS_MASTER_BLSP_2,
	MSM_BUS_MASTER_USB_HSIC,
	MSM_BUS_MASTER_BLSP_1,
	MSM_BUS_MASTER_USB_HS,
	MSM_BUS_MASTER_PNOC_CFG,
	MSM_BUS_MASTER_V_OCMEM_GFX3D,
	MSM_BUS_MASTER_IPA,
	MSM_BUS_MASTER_QPIC,
	MSM_BUS_MASTER_MDPE,

	MSM_BUS_MASTER_LAST,

	MSM_BUS_SYSTEM_FPB_MASTER_SYSTEM =
		MSM_BUS_SYSTEM_MASTER_SYSTEM_FPB,
	MSM_BUS_CPSS_FPB_MASTER_SYSTEM =
		MSM_BUS_SYSTEM_MASTER_CPSS_FPB,
};


static struct resource msm_device_vidc_resources[] = {
	{
		.start	= MSM_VIDC_BASE_PHYS,
		.end	= MSM_VIDC_BASE_PHYS + MSM_VIDC_BASE_SIZE - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= VCODEC_IRQ,
		.end	= VCODEC_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct msm_bus_vectors vidc_init_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 0,
		.ib  = 0,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 0,
		.ib  = 0,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};
static struct msm_bus_vectors vidc_venc_vga_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 54525952,
		.ib  = 436207616,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 72351744,
		.ib  = 289406976,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 500000,
		.ib  = 1000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 500000,
		.ib  = 1000000,
	},
};
static struct msm_bus_vectors vidc_vdec_vga_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 40894464,
		.ib  = 327155712,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 48234496,
		.ib  = 192937984,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 500000,
		.ib  = 2000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 500000,
		.ib  = 2000000,
	},
};
static struct msm_bus_vectors vidc_venc_720p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 163577856,
		.ib  = 1308622848,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 219152384,
		.ib  = 876609536,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 1750000,
		.ib  = 3500000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 1750000,
		.ib  = 3500000,
	},
};
static struct msm_bus_vectors vidc_vdec_720p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 121634816,
		.ib  = 973078528,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 155189248,
		.ib  = 620756992,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 1750000,
		.ib  = 7000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 1750000,
		.ib  = 7000000,
	},
};
static struct msm_bus_vectors vidc_venc_1080p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 372244480,
		.ib  = 2560000000U,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 501219328,
		.ib  = 2560000000U,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 5000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 5000000,
	},
};
static struct msm_bus_vectors vidc_vdec_1080p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 222298112,
		.ib  = 2560000000U,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 330301440,
		.ib  = 2560000000U,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 700000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 10000000,
	},
};
static struct msm_bus_vectors vidc_venc_1080p_turbo_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 222298112,
		.ib  = 3522000000U,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 330301440,
		.ib  = 3522000000U,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 700000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 10000000,
	},
};
static struct msm_bus_vectors vidc_vdec_1080p_turbo_vectors[] = {
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 222298112,
		.ib  = 3522000000U,
	},
	{
		.src = MSM_BUS_MASTER_HD_CODEC_PORT1,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 330301440,
		.ib  = 3522000000U,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 700000000,
	},
	{
		.src = MSM_BUS_MASTER_AMPSS_M0,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = 2500000,
		.ib  = 10000000,
	},
};

static struct msm_bus_paths vidc_bus_client_config[] = {
	{
		ARRAY_SIZE(vidc_init_vectors),
		vidc_init_vectors,
	},
	{
		ARRAY_SIZE(vidc_venc_vga_vectors),
		vidc_venc_vga_vectors,
	},
	{
		ARRAY_SIZE(vidc_vdec_vga_vectors),
		vidc_vdec_vga_vectors,
	},
	{
		ARRAY_SIZE(vidc_venc_720p_vectors),
		vidc_venc_720p_vectors,
	},
	{
		ARRAY_SIZE(vidc_vdec_720p_vectors),
		vidc_vdec_720p_vectors,
	},
	{
		ARRAY_SIZE(vidc_venc_1080p_vectors),
		vidc_venc_1080p_vectors,
	},
	{
		ARRAY_SIZE(vidc_vdec_1080p_vectors),
		vidc_vdec_1080p_vectors,
	},
	{
		ARRAY_SIZE(vidc_venc_1080p_turbo_vectors),
		vidc_venc_1080p_turbo_vectors,
	},
	{
		ARRAY_SIZE(vidc_vdec_1080p_turbo_vectors),
		vidc_vdec_1080p_turbo_vectors,
	},
};


static struct msm_bus_scale_pdata vidc_bus_client_data = {
	vidc_bus_client_config,
	ARRAY_SIZE(vidc_bus_client_config),
	.name = "vidc",
};


struct msm_vidc_platform_data vidc_platform_data = {
//#ifdef CONFIG_MSM_BUS_SCALING
	.vidc_bus_client_pdata = &vidc_bus_client_data,
//#endif
//#ifdef CONFIG_MSM_MULTIMEDIA_USE_ION
	.memtype = ION_CP_MM_HEAP_ID,
	.enable_ion = 1,
	.cp_enabled = 1,
//#else
//	.memtype = MEMTYPE_EBI1,
//	.enable_ion = 0,
//#endif
	.disable_dmx = 0,
	.disable_fullhd = 0,
	.cont_mode_dpb_count = 18,
	.fw_addr = 0x9fe00000,
	.enable_sec_metadata = 0,
};

struct platform_device msm_device_vidc = {
	.name = "msm_vidc",
	.id = 0,
	.num_resources = ARRAY_SIZE(msm_device_vidc_resources),
	.resource = msm_device_vidc_resources,
	.dev = {
		.platform_data	= &vidc_platform_data,
	},
};


/*
 * msm_vidc end
 */


/*
 * QFEC begin
 */

#define INT_SBD_IRQ		28
# define QFEC_MAC_IRQ           INT_SBD_IRQ
# define QFEC_MAC_BASE          0x40000000
# define QFEC_CLK_BASE          0x94020000

# define QFEC_MAC_SIZE          0x2000
# define QFEC_CLK_SIZE          0x18100

# define QFEC_MAC_FUSE_BASE     0x80004210
# define QFEC_MAC_FUSE_SIZE     16

static struct resource qfec_resources[] = {
	[0] = {
		.start = QFEC_MAC_BASE,
		.end   = QFEC_MAC_BASE + QFEC_MAC_SIZE,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start = QFEC_MAC_IRQ,
		.end   = QFEC_MAC_IRQ,
		.flags = IORESOURCE_IRQ,
	},
	[2] = {
		//.start = QFEC_CLK_BASE,
		//.end   = QFEC_CLK_BASE + QFEC_CLK_SIZE,
                //.start	= 0xfd530000,
		//.end	= 0xfd530000 + 0x100 - 1,
		//.start = 0x1000,
		//.end   = 0x1000 + 16 - 1,
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO,
	},
	[3] = {
		.start = QFEC_MAC_FUSE_BASE,
		.end   = QFEC_MAC_FUSE_BASE + QFEC_MAC_FUSE_SIZE,
		.flags = IORESOURCE_DMA,
	},
};

struct platform_device qfec_device = {
	.name           = "qfec",
	.id             = 0,
	.num_resources  = ARRAY_SIZE(qfec_resources),
	.resource       = qfec_resources,
};

/*
 * QFEC end
 */



/* SMUX_RMNET begin */
static struct platform_device smux_devs[] = {
	{.name = "SMUX_CTL", .id = -1},
	{.name = "SMUX_RMNET", .id = -1},
	{.name = "SMUX_DUN_DATA_HSUART", .id = 0},
	{.name = "SMUX_RMNET_DATA_HSUART", .id = 1},
	{.name = "SMUX_RMNET_CTL_HSUART", .id = 0},
	{.name = "SMUX_DIAG", .id = -1},
};
/* SMUX_RMNET end */

/* msm_vpe begin */

#define INT_VPE			(64 + 17)
static struct resource msm_vpe_resources[] = {
	{
		.start	= 0x05300000,
		.end	= 0x05300000 + SZ_1M - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= INT_VPE,
		.end	= INT_VPE,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device msm_vpe_device = {
	.name = "msm_vpe",
	.id   = 0,
	.num_resources = ARRAY_SIZE(msm_vpe_resources),
	.resource = msm_vpe_resources,
};
/* msm_vpe end */


/* msm_gemini begin */

#define INT_JPEG		(64 + 22)
static struct resource msm_gemini_resources[] = {
	{
		.start  = 0x04600000,
		.end    = 0x04600000 + SZ_1M - 1,
		.flags  = IORESOURCE_MEM,
	},
	{
		.start  = INT_JPEG,
		.end    = INT_JPEG,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct platform_device msm_gemini_device = {
	.name           = "msm_gemini",
	.resource       = msm_gemini_resources,
	.num_resources  = ARRAY_SIZE(msm_gemini_resources),
};
/* msm_gemini end */


/* msm_cam_i2c_mux begin */
static struct resource msm_cam_gsbi4_i2c_mux_resources[] = {
	{
		.name   = "i2c_mux_rw",
		.start  = 0x008003E0,
		.end    = 0x008003E0 + SZ_8 - 1,
		.flags  = IORESOURCE_MEM,
	},
	{
		.name   = "i2c_mux_ctl",
		.start  = 0x008020B8,
		.end    = 0x008020B8 + SZ_4 - 1,
		.flags  = IORESOURCE_MEM,
	},
};

struct platform_device msm_cam_i2c_mux = { //msm8960_device_i2c_mux_gsbi4 = {
	.name           = "msm_cam_i2c_mux",
	.id             = 0,
	.resource       = msm_cam_gsbi4_i2c_mux_resources,
	.num_resources  = ARRAY_SIZE(msm_cam_gsbi4_i2c_mux_resources),
};
/* msm_cam_i2c_mux end */

/* avtimer device begin */
#define AVTIMER_MSW_PHYSICAL_ADDRESS 0x2800900C
#define AVTIMER_LSW_PHYSICAL_ADDRESS 0x28009008

struct dev_avtimer_data {
	uint32_t avtimer_msw_phy_addr;
	uint32_t avtimer_lsw_phy_addr;
};

struct dev_avtimer_data dev_avtimer_pdata = {
	.avtimer_msw_phy_addr = AVTIMER_MSW_PHYSICAL_ADDRESS,
	.avtimer_lsw_phy_addr = AVTIMER_LSW_PHYSICAL_ADDRESS,
};
static struct platform_device msm_dev_avtimer_device = {
	.name = "dev_avtimer",
	.dev = { .platform_data = &dev_avtimer_pdata },
};


/* avtimer device end */

/* msm_rotator device begin */

//#define GIC_SPI_START 32
//#define IORESOURCE_MEM		0x00000200
//#define ROT_IRQ					(GIC_SPI_START + 73)
//#define IORESOURCE_IRQ		0x00000400
//#define FABRIC_ID_KEY 1024
//#define SLAVE_ID_KEY ((FABRIC_ID_KEY) >> 1)
//enum msm_bus_fabric_slave_type {
//	MSM_BUS_SLAVE_FIRST = SLAVE_ID_KEY,
//	MSM_BUS_SLAVE_EBI_CH0 = SLAVE_ID_KEY,
//	MSM_BUS_SLAVE_EBI_CH1,
//	MSM_BUS_SLAVE_AMPSS_L2,
//	MSM_BUS_APPSS_SLAVE_FAB_MMSS,
//	MSM_BUS_APPSS_SLAVE_FAB_SYSTEM,
//
//	MSM_BUS_SYSTEM_SLAVE_FAB_APPS,
//	MSM_BUS_SLAVE_SPS,
//	MSM_BUS_SLAVE_SYSTEM_IMEM,
//	MSM_BUS_SLAVE_AMPSS,
//	MSM_BUS_SLAVE_MSS,
//	MSM_BUS_SLAVE_LPASS,
//	MSM_BUS_SYSTEM_SLAVE_CPSS_FPB,
//	MSM_BUS_SYSTEM_SLAVE_SYSTEM_FPB,
//	MSM_BUS_SYSTEM_SLAVE_MMSS_FPB,
//	MSM_BUS_SLAVE_CORESIGHT,
//	MSM_BUS_SLAVE_RIVA,
//
//	MSM_BUS_SLAVE_SMI,
//	MSM_BUS_MMSS_SLAVE_FAB_APPS,
//	MSM_BUS_MMSS_SLAVE_FAB_APPS_1,
//	MSM_BUS_SLAVE_MM_IMEM,
//	MSM_BUS_SLAVE_CRYPTO,
//
//	MSM_BUS_SLAVE_SPDM,
//	MSM_BUS_SLAVE_RPM,
//	MSM_BUS_SLAVE_RPM_MSG_RAM,
//	MSM_BUS_SLAVE_MPM,
//	MSM_BUS_SLAVE_PMIC1_SSBI1_A,
//	MSM_BUS_SLAVE_PMIC1_SSBI1_B,
//	MSM_BUS_SLAVE_PMIC1_SSBI1_C,
//	MSM_BUS_SLAVE_PMIC2_SSBI2_A,
//	MSM_BUS_SLAVE_PMIC2_SSBI2_B,
//
//	MSM_BUS_SLAVE_GSBI1_UART,
//	MSM_BUS_SLAVE_GSBI2_UART,
//	MSM_BUS_SLAVE_GSBI3_UART,
//	MSM_BUS_SLAVE_GSBI4_UART,
//	MSM_BUS_SLAVE_GSBI5_UART,
//	MSM_BUS_SLAVE_GSBI6_UART,
//	MSM_BUS_SLAVE_GSBI7_UART,
//	MSM_BUS_SLAVE_GSBI8_UART,
//	MSM_BUS_SLAVE_GSBI9_UART,
//	MSM_BUS_SLAVE_GSBI10_UART,
//	MSM_BUS_SLAVE_GSBI11_UART,
//	MSM_BUS_SLAVE_GSBI12_UART,
//	MSM_BUS_SLAVE_GSBI1_QUP,
//	MSM_BUS_SLAVE_GSBI2_QUP,
//	MSM_BUS_SLAVE_GSBI3_QUP,
//	MSM_BUS_SLAVE_GSBI4_QUP,
//	MSM_BUS_SLAVE_GSBI5_QUP,
//	MSM_BUS_SLAVE_GSBI6_QUP,
//	MSM_BUS_SLAVE_GSBI7_QUP,
//	MSM_BUS_SLAVE_GSBI8_QUP,
//	MSM_BUS_SLAVE_GSBI9_QUP,
//	MSM_BUS_SLAVE_GSBI10_QUP,
//	MSM_BUS_SLAVE_GSBI11_QUP,
//	MSM_BUS_SLAVE_GSBI12_QUP,
//	MSM_BUS_SLAVE_EBI2_NAND,
//	MSM_BUS_SLAVE_EBI2_CS0,
//	MSM_BUS_SLAVE_EBI2_CS1,
//	MSM_BUS_SLAVE_EBI2_CS2,
//	MSM_BUS_SLAVE_EBI2_CS3,
//	MSM_BUS_SLAVE_EBI2_CS4,
//	MSM_BUS_SLAVE_EBI2_CS5,
//	MSM_BUS_SLAVE_USB_FS1,
//	MSM_BUS_SLAVE_USB_FS2,
//	MSM_BUS_SLAVE_TSIF,
//	MSM_BUS_SLAVE_MSM_TSSC,
//	MSM_BUS_SLAVE_MSM_PDM,
//	MSM_BUS_SLAVE_MSM_DIMEM,
//	MSM_BUS_SLAVE_MSM_TCSR,
//	MSM_BUS_SLAVE_MSM_PRNG,
//	MSM_BUS_SLAVE_GSS,
//	MSM_BUS_SLAVE_SATA,
//
//	MSM_BUS_SLAVE_USB3,
//	MSM_BUS_SLAVE_WCSS,
//	MSM_BUS_SLAVE_OCIMEM,
//	MSM_BUS_SLAVE_SNOC_OCMEM,
//	MSM_BUS_SLAVE_SERVICE_SNOC,
//	MSM_BUS_SLAVE_QDSS_STM,
//
//	MSM_BUS_SLAVE_CAMERA_CFG,
//	MSM_BUS_SLAVE_DISPLAY_CFG,
//	MSM_BUS_SLAVE_OCMEM_CFG,
//	MSM_BUS_SLAVE_CPR_CFG,
//	MSM_BUS_SLAVE_CPR_XPU_CFG,
//	MSM_BUS_SLAVE_MISC_CFG,
//	MSM_BUS_SLAVE_MISC_XPU_CFG,
//	MSM_BUS_SLAVE_VENUS_CFG,
//	MSM_BUS_SLAVE_MISC_VENUS_CFG,
//	MSM_BUS_SLAVE_GRAPHICS_3D_CFG,
//	MSM_BUS_SLAVE_MMSS_CLK_CFG,
//	MSM_BUS_SLAVE_MMSS_CLK_XPU_CFG,
//	MSM_BUS_SLAVE_MNOC_MPU_CFG,
//	MSM_BUS_SLAVE_ONOC_MPU_CFG,
//	MSM_BUS_SLAVE_SERVICE_MNOC,
//
//	MSM_BUS_SLAVE_OCMEM,
//	MSM_BUS_SLAVE_SERVICE_ONOC,
//
//	MSM_BUS_SLAVE_SDCC_1,
//	MSM_BUS_SLAVE_SDCC_3,
//	MSM_BUS_SLAVE_SDCC_2,
//	MSM_BUS_SLAVE_SDCC_4,
//	MSM_BUS_SLAVE_BAM_DMA,
//	MSM_BUS_SLAVE_BLSP_2,
//	MSM_BUS_SLAVE_USB_HSIC,
//	MSM_BUS_SLAVE_BLSP_1,
//	MSM_BUS_SLAVE_USB_HS,
//	MSM_BUS_SLAVE_PDM,
//	MSM_BUS_SLAVE_PERIPH_APU_CFG,
//	MSM_BUS_SLAVE_PNOC_MPU_CFG,
//	MSM_BUS_SLAVE_PRNG,
//	MSM_BUS_SLAVE_SERVICE_PNOC,
//
//	MSM_BUS_SLAVE_CLK_CTL,
//	MSM_BUS_SLAVE_CNOC_MSS,
//	MSM_BUS_SLAVE_SECURITY,
//	MSM_BUS_SLAVE_TCSR,
//	MSM_BUS_SLAVE_TLMM,
//	MSM_BUS_SLAVE_CRYPTO_0_CFG,
//	MSM_BUS_SLAVE_CRYPTO_1_CFG,
//	MSM_BUS_SLAVE_IMEM_CFG,
//	MSM_BUS_SLAVE_MESSAGE_RAM,
//	MSM_BUS_SLAVE_BIMC_CFG,
//	MSM_BUS_SLAVE_BOOT_ROM,
//	MSM_BUS_SLAVE_CNOC_MNOC_MMSS_CFG,
//	MSM_BUS_SLAVE_PMIC_ARB,
//	MSM_BUS_SLAVE_SPDM_WRAPPER,
//	MSM_BUS_SLAVE_DEHR_CFG,
//	MSM_BUS_SLAVE_QDSS_CFG,
//	MSM_BUS_SLAVE_RBCPR_CFG,
//	MSM_BUS_SLAVE_RBCPR_QDSS_APU_CFG,
//	MSM_BUS_SLAVE_SNOC_MPU_CFG,
//	MSM_BUS_SLAVE_CNOC_ONOC_CFG,
//	MSM_BUS_SLAVE_CNOC_MNOC_CFG,
//	MSM_BUS_SLAVE_PNOC_CFG,
//	MSM_BUS_SLAVE_SNOC_CFG,
//	MSM_BUS_SLAVE_EBI1_DLL_CFG,
//	MSM_BUS_SLAVE_PHY_APU_CFG,
//	MSM_BUS_SLAVE_EBI1_PHY_CFG,
//	MSM_BUS_SLAVE_SERVICE_CNOC,
//	MSM_BUS_SLAVE_IPS_CFG,
//	MSM_BUS_SLAVE_QPIC,
//	MSM_BUS_SLAVE_DSI_CFG,
//
//	MSM_BUS_SLAVE_LAST,
//
//	MSM_BUS_SYSTEM_FPB_SLAVE_SYSTEM =
//		MSM_BUS_SYSTEM_SLAVE_SYSTEM_FPB,
//	MSM_BUS_CPSS_FPB_SLAVE_SYSTEM =
//		MSM_BUS_SYSTEM_SLAVE_CPSS_FPB,
//};
//enum msm_bus_fabric_master_type {
//	MSM_BUS_MASTER_FIRST = 1,
//	MSM_BUS_MASTER_AMPSS_M0 = 1,
//	MSM_BUS_MASTER_AMPSS_M1,
//	MSM_BUS_APPSS_MASTER_FAB_MMSS,
//	MSM_BUS_APPSS_MASTER_FAB_SYSTEM,
//
//	MSM_BUS_SYSTEM_MASTER_FAB_APPSS,
//	MSM_BUS_MASTER_SPS,
//	MSM_BUS_MASTER_ADM_PORT0,
//	MSM_BUS_MASTER_ADM_PORT1,
//	MSM_BUS_SYSTEM_MASTER_ADM1_PORT0,
//	MSM_BUS_MASTER_ADM1_PORT1,
//	MSM_BUS_MASTER_LPASS_PROC,
//	MSM_BUS_MASTER_MSS_PROCI,
//	MSM_BUS_MASTER_MSS_PROCD,
//	MSM_BUS_MASTER_MSS_MDM_PORT0,
//	MSM_BUS_MASTER_LPASS,
//	MSM_BUS_SYSTEM_MASTER_CPSS_FPB,
//	MSM_BUS_SYSTEM_MASTER_SYSTEM_FPB,
//	MSM_BUS_SYSTEM_MASTER_MMSS_FPB,
//	MSM_BUS_MASTER_ADM1_CI,
//	MSM_BUS_MASTER_ADM0_CI,
//	MSM_BUS_MASTER_MSS_MDM_PORT1,
//
//	MSM_BUS_MASTER_MDP_PORT0,
//	MSM_BUS_MASTER_MDP_PORT1,
//	MSM_BUS_MMSS_MASTER_ADM1_PORT0,
//	MSM_BUS_MASTER_ROTATOR,
//	MSM_BUS_MASTER_GRAPHICS_3D,
//	MSM_BUS_MASTER_JPEG_DEC,
//	MSM_BUS_MASTER_GRAPHICS_2D_CORE0,
//	MSM_BUS_MASTER_VFE,
//	MSM_BUS_MASTER_VPE,
//	MSM_BUS_MASTER_JPEG_ENC,
//	MSM_BUS_MASTER_GRAPHICS_2D_CORE1,
//	MSM_BUS_MMSS_MASTER_APPS_FAB,
//	MSM_BUS_MASTER_HD_CODEC_PORT0,
//	MSM_BUS_MASTER_HD_CODEC_PORT1,
//
//	MSM_BUS_MASTER_SPDM,
//	MSM_BUS_MASTER_RPM,
//
//	MSM_BUS_MASTER_MSS,
//	MSM_BUS_MASTER_RIVA,
//	MSM_BUS_SYSTEM_MASTER_UNUSED_6,
//	MSM_BUS_MASTER_MSS_SW_PROC,
//	MSM_BUS_MASTER_MSS_FW_PROC,
//	MSM_BUS_MMSS_MASTER_UNUSED_2,
//	MSM_BUS_MASTER_GSS_NAV,
//	MSM_BUS_MASTER_PCIE,
//	MSM_BUS_MASTER_SATA,
//	MSM_BUS_MASTER_CRYPTO,
//
//	MSM_BUS_MASTER_VIDEO_CAP,
//	MSM_BUS_MASTER_GRAPHICS_3D_PORT1,
//	MSM_BUS_MASTER_VIDEO_ENC,
//	MSM_BUS_MASTER_VIDEO_DEC,
//
//	MSM_BUS_MASTER_LPASS_AHB,
//	MSM_BUS_MASTER_QDSS_BAM,
//	MSM_BUS_MASTER_SNOC_CFG,
//	MSM_BUS_MASTER_CRYPTO_CORE0,
//	MSM_BUS_MASTER_CRYPTO_CORE1,
//	MSM_BUS_MASTER_MSS_NAV,
//	MSM_BUS_MASTER_OCMEM_DMA,
//	MSM_BUS_MASTER_WCSS,
//	MSM_BUS_MASTER_QDSS_ETR,
//	MSM_BUS_MASTER_USB3,
//
//	MSM_BUS_MASTER_JPEG,
//	MSM_BUS_MASTER_VIDEO_P0,
//	MSM_BUS_MASTER_VIDEO_P1,
//
//	MSM_BUS_MASTER_MSS_PROC,
//	MSM_BUS_MASTER_JPEG_OCMEM,
//	MSM_BUS_MASTER_MDP_OCMEM,
//	MSM_BUS_MASTER_VIDEO_P0_OCMEM,
//	MSM_BUS_MASTER_VIDEO_P1_OCMEM,
//	MSM_BUS_MASTER_VFE_OCMEM,
//	MSM_BUS_MASTER_CNOC_ONOC_CFG,
//	MSM_BUS_MASTER_RPM_INST,
//	MSM_BUS_MASTER_RPM_DATA,
//	MSM_BUS_MASTER_RPM_SYS,
//	MSM_BUS_MASTER_DEHR,
//	MSM_BUS_MASTER_QDSS_DAP,
//	MSM_BUS_MASTER_TIC,
//
//	MSM_BUS_MASTER_SDCC_1,
//	MSM_BUS_MASTER_SDCC_3,
//	MSM_BUS_MASTER_SDCC_4,
//	MSM_BUS_MASTER_SDCC_2,
//	MSM_BUS_MASTER_TSIF,
//	MSM_BUS_MASTER_BAM_DMA,
//	MSM_BUS_MASTER_BLSP_2,
//	MSM_BUS_MASTER_USB_HSIC,
//	MSM_BUS_MASTER_BLSP_1,
//	MSM_BUS_MASTER_USB_HS,
//	MSM_BUS_MASTER_PNOC_CFG,
//	MSM_BUS_MASTER_V_OCMEM_GFX3D,
//	MSM_BUS_MASTER_IPA,
//	MSM_BUS_MASTER_QPIC,
//	MSM_BUS_MASTER_MDPE,
//
//	MSM_BUS_MASTER_LAST,
//
//	MSM_BUS_SYSTEM_FPB_MASTER_SYSTEM =
//		MSM_BUS_SYSTEM_MASTER_SYSTEM_FPB,
//	MSM_BUS_CPSS_FPB_MASTER_SYSTEM =
//		MSM_BUS_SYSTEM_MASTER_CPSS_FPB,
//};
enum rotator_clk_type {
	ROTATOR_CORE_CLK,
	ROTATOR_PCLK,
	ROTATOR_IMEM_CLK
};
struct msm_rot_clocks {
	const char *clk_name;
	enum rotator_clk_type clk_type;
	unsigned int clk_rate;
};
//struct msm_bus_paths {
//	int num_paths;
//	struct msm_bus_vectors *vectors;
//};

//struct msm_bus_vectors {
//	int src; /* Master */
//	int dst; /* Slave */
//	uint64_t ab; /* Arbitrated bandwidth */
//	uint64_t ib; /* Instantaneous bandwidth */
//};
static struct msm_bus_vectors rotator_init_vectors[] = {
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab = 0,
		.ib = 0,
	},
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab = 0,
		.ib = 0,
	},
};

static struct msm_bus_vectors rotator_ui_vectors[] = {
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab  = 0,
		.ib  = 0,
	},
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = (1024 * 600 * 4 * 2 * 60),
		.ib  = (1024 * 600 * 4 * 2 * 60 * 1.5),
	},
};

static struct msm_bus_vectors rotator_vga_vectors[] = {
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab  = (640 * 480 * 2 * 2 * 30),
		.ib  = (640 * 480 * 2 * 2 * 30 * 1.5),
	},
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = (640 * 480 * 2 * 2 * 30),
		.ib  = (640 * 480 * 2 * 2 * 30 * 1.5),
	},
};

static struct msm_bus_vectors rotator_720p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab  = (1280 * 736 * 2 * 2 * 30),
		.ib  = (1280 * 736 * 2 * 2 * 30 * 1.5),
	},
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = (1280 * 736 * 2 * 2 * 30),
		.ib  = (1280 * 736 * 2 * 2 * 30 * 1.5),
	},
};

static struct msm_bus_vectors rotator_1080p_vectors[] = {
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_SMI,
		.ab  = (1920 * 1088 * 2 * 2 * 30),
		.ib  = (1920 * 1088 * 2 * 2 * 30 * 1.5),
	},
	{
		.src = MSM_BUS_MASTER_ROTATOR,
		.dst = MSM_BUS_SLAVE_EBI_CH0,
		.ab  = (1920 * 1088 * 2 * 2 * 30),
		.ib  = (1920 * 1088 * 2 * 2 * 30 * 1.5),
	},
};
static struct msm_bus_paths rotator_bus_scale_usecases[] = {
	{
		ARRAY_SIZE(rotator_init_vectors),
		rotator_init_vectors,
	},
	{
		ARRAY_SIZE(rotator_ui_vectors),
		rotator_ui_vectors,
	},
	{
		ARRAY_SIZE(rotator_vga_vectors),
		rotator_vga_vectors,
	},
	{
		ARRAY_SIZE(rotator_720p_vectors),
		rotator_720p_vectors,
	},
	{
		ARRAY_SIZE(rotator_1080p_vectors),
		rotator_1080p_vectors,
	},
};
//struct msm_bus_scale_pdata {
//	struct msm_bus_paths *usecase;
//	int num_usecases;
//	const char *name;
//	/*
//	 * If the active_only flag is set to 1, the BW request is applied
//	 * only when at least one CPU is active (powered on). If the flag
//	 * is set to 0, then the BW request is always applied irrespective
//	 * of the CPU state.
//	 */
//	unsigned int active_only;
//};
struct msm_bus_scale_pdata rotator_bus_scale_pdata = {
	rotator_bus_scale_usecases,
	ARRAY_SIZE(rotator_bus_scale_usecases),
	.name = "rotator",
};
static struct msm_rot_clocks rotator_clocks[] = {
	{
		.clk_name = "core_clk",
		.clk_type = ROTATOR_CORE_CLK,
		.clk_rate = 160 * 1000 * 1000,
	},
	{
		.clk_name = "iface_clk",
		.clk_type = ROTATOR_PCLK,
		.clk_rate = 0,
	},
};

struct msm_rotator_platform_data {
	unsigned int number_of_clocks;
	unsigned int hardware_version_number;
	struct msm_rot_clocks *rotator_clks;
//#ifdef CONFIG_MSM_BUS_SCALING
	struct msm_bus_scale_pdata *bus_scale_table;
//#endif
	char rot_iommu_split_domain;
};
static struct msm_rotator_platform_data rotator_pdata = {
	.number_of_clocks = ARRAY_SIZE(rotator_clocks),
	.hardware_version_number = 0x01010307,
	.rotator_clks = rotator_clocks,
//#ifdef CONFIG_MSM_BUS_SCALING
	.bus_scale_table = &rotator_bus_scale_pdata,
//#endif
	.rot_iommu_split_domain = 0,
};
static struct resource resources_msm_rotator[] = {
	{
		.start	= 0x04E00000,
		.end	= 0x04F00000 - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= ROT_IRQ,
		.end	= ROT_IRQ,
		.flags	= IORESOURCE_IRQ,
	},
};
struct platform_device msm_rotator_device = {
	.name		= "msm_rotator",
	.id		= 0,
	.num_resources  = ARRAY_SIZE(resources_msm_rotator),
	.resource       = resources_msm_rotator,
	.dev		= {
		.platform_data = &rotator_pdata,
	},
};

/* msm_rotator device end */


/* msm_adc device begin */
enum {
	ADC_CONFIG_TYPE1,
	ADC_CONFIG_TYPE2,
	ADC_CONFIG_NONE = 0xffffffff
};

enum {
	ADC_CALIB_CONFIG_TYPE1,
	ADC_CALIB_CONFIG_TYPE2,
	ADC_CALIB_CONFIG_TYPE3,
	ADC_CALIB_CONFIG_TYPE4,
	ADC_CALIB_CONFIG_TYPE5,
	ADC_CALIB_CONFIG_TYPE6,
	ADC_CALIB_CONFIG_TYPE7,
	ADC_CALIB_CONFIG_NONE = 0xffffffff
};

enum {
	/* CHAN_PATH_TYPEn is specific for each ADC driver
	and can be used however way it wants*/
	CHAN_PATH_TYPE1,
	CHAN_PATH_TYPE2,
	CHAN_PATH_TYPE3,
	CHAN_PATH_TYPE4,
	CHAN_PATH_TYPE5,
	CHAN_PATH_TYPE6,
	CHAN_PATH_TYPE7,
	CHAN_PATH_TYPE8,
	CHAN_PATH_TYPE9,
	CHAN_PATH_TYPE10,
	CHAN_PATH_TYPE11,
	CHAN_PATH_TYPE12,
	CHAN_PATH_TYPE13,
	CHAN_PATH_TYPE14,
	CHAN_PATH_TYPE15,
	CHAN_PATH_TYPE16,
	/* A given channel connects directly to the ADC */
	CHAN_PATH_TYPE_NONE = 0xffffffff
};
#define CHANNEL_ADC_BATT_ID     0
#define CHANNEL_ADC_BATT_THERM  1
#define CHANNEL_ADC_BATT_AMON   2
#define CHANNEL_ADC_VBATT       3
#define CHANNEL_ADC_VCOIN       4
#define CHANNEL_ADC_VCHG        5
#define CHANNEL_ADC_CHG_MONITOR 6
#define CHANNEL_ADC_VPH_PWR     7
#define CHANNEL_ADC_USB_VBUS    8
#define CHANNEL_ADC_DIE_TEMP    9
#define CHANNEL_ADC_DIE_TEMP_4K 0xa
#define CHANNEL_ADC_XOTHERM     0xb
#define CHANNEL_ADC_XOTHERM_4K  0xc
#define CHANNEL_ADC_HDSET       0xd
#define CHANNEL_ADC_MSM_THERM	0xe
#define CHANNEL_ADC_625_REF	0xf
#define CHANNEL_ADC_1250_REF	0x10
#define CHANNEL_ADC_325_REF	0x11
#define CHANNEL_ADC_FSM_THERM	0x12
#define CHANNEL_ADC_PA_THERM	0x13
struct adc_chan_result {
	/* The channel number of the requesting/requested conversion */
	uint32_t chan;
	/* The pre-calibrated digital output of a given ADC relative to the
	ADC reference */
	int32_t adc_code;
	/* in units specific for a given ADC; most ADC uses reference voltage
	 *  but some ADC uses reference current.  This measurement here is
	 *  a number relative to a reference of a given ADC */
	int64_t measurement;
	/* The data meaningful for each individual channel whether it is
	 * voltage, current, temperature, etc. */
	int64_t physical;
};
struct chan_properties {
	uint32_t gain_numerator;
	uint32_t gain_denominator;
	struct linear_graph *adc_graph;
/* this maybe the same as adc_properties.ConversionTime
   if channel does not change the adc properties */
	uint32_t chan_conv_time;
};
struct adc_properties {
	uint32_t adc_reference; /* milli-voltage for this adc */
	uint32_t bitresolution;
	bool bipolar;
	uint32_t conversiontime;
};
struct msm_adc_channels {
	char *name;
	uint32_t channel_name;
	uint32_t adc_dev_instance;
	struct adc_access_fn *adc_access_fn;
	uint32_t chan_path_type;
	uint32_t adc_config_type;
	uint32_t adc_calib_type;
	int32_t (*chan_processor)(int32_t, const struct adc_properties *,
		const struct chan_properties *, struct adc_chan_result *);

};
static struct msm_adc_channels msm_adc_channels_data[] = {
	{"vbatt", CHANNEL_ADC_VBATT, 0, NULL, CHAN_PATH_TYPE2,
		ADC_CONFIG_TYPE2, ADC_CALIB_CONFIG_TYPE3, NULL},
};
struct msm_adc_platform_data {
	struct msm_adc_channels *channel;
	uint32_t num_chan_supported;
	uint32_t num_adc;
	uint32_t chan_per_adc;
	char **dev_names;
	uint32_t target_hw;
	uint32_t gpio_config;
	u32 (*adc_gpio_enable) (int);
	u32 (*adc_gpio_disable) (int);
	u32 (*adc_fluid_enable) (void);
	u32 (*adc_fluid_disable) (void);
};
static struct msm_adc_platform_data msm_adc_pdata = {
	.channel = msm_adc_channels_data,
	.num_chan_supported = ARRAY_SIZE(msm_adc_channels_data),
};

static struct platform_device msm_adc_device = {
	.name   = "msm_adc",
	.id = -1,
	.dev = {
		.platform_data = &msm_adc_pdata,
	},
};

/* msm_adc device end */

/*** AVAILABLE DEVICES END **/
static struct platform_device *available_devices[] = {&msm_dev_avtimer_device,
                                                      &msm_rotator_device,
                                                      &msm_adc_device,
                                                      &msm_cam_i2c_mux,
                                                      &msm_gemini_device,
						      &msm_vpe_device,
					              &smux_devs[1],
						      &qfec_device,
                                                      &msm_device_vidc,
						      0};

static struct platform_device *get_platform_device_by_name(char *dev_name)
{
  int i = 0;
  struct platform_device *pdev = available_devices[0];
  printk("%s(): dev_name = %s\n", __func__, dev_name);
  while(pdev)
  {
    printk("%s(): pdev->name = %s\n", __func__, pdev->name);
    if (!strcmp(pdev->name, dev_name))
      return pdev;
    i++;
    pdev = available_devices[i];
  }
  return NULL;
}


static struct file_operations self_fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};


/* In this function we create a char device using which we can
   tell the device creator driver the name of the device to create */
static int __init dcreator_init(void)
{
   printk("devicecreator: Initializing\n");

   // Try to dynamically allocate a major number for the device
   majorNumber = register_chrdev(0, SELF_DEVICE_NAME, &self_fops);
   if (majorNumber<0){
      printk("device creator failed to register a major number\n");
      return majorNumber;
   }
   printk("device creator: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   selfClass = class_create(THIS_MODULE, SELF_CLASS_NAME);
   if (IS_ERR(selfClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, SELF_DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(selfClass);          // Correct way to return an error on a pointer
   }
   printk("device creator: device class registered correctly\n");

   // Register the device driver
   selfDevice = device_create(selfClass, NULL, MKDEV(majorNumber, 0), NULL, SELF_DEVICE_NAME);
   if (IS_ERR(selfDevice)){               // Clean up if there is an error
      class_destroy(selfClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, SELF_DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(selfDevice);
   }
   printk("device creator: device class created correctly\n");
   return 0;
}


static void __exit dcreator_exit(void){
   device_destroy(selfClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(selfClass);                          // unregister the device class
   class_destroy(selfClass);                             // remove the device class
   unregister_chrdev(majorNumber, SELF_DEVICE_NAME);             // unregister the major number
   printk("dcreator: dev file removed\n");
}


/* Nothing to do here, just open the device */
static int dev_open(struct inode *inodep, struct file *filep){
   return 0;
}

/* List the name of platform device that we can register */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
  char out[1024];
  ssize_t nbytes_to_copy; /* number of byte to copy to the user */
  int i = 0;
  char *p = &out[0];
  size_t out_len=0;
  struct platform_device *pdev = available_devices[0];
  //printk("%s(): len = %d, offset = %lld\n", __func__, len, *offset);
  while(pdev)
  {
    sprintf(p, "%s ", pdev->name);
    i++;
    p = p + strlen(pdev->name)+1;
    out_len = out_len + strlen(pdev->name)+1;
    pdev = available_devices[i];
  }
  out[out_len]='\0';
  out_len++;

  if(*offset >= out_len)
    return 0;

  nbytes_to_copy = min(out_len - (size_t)(*offset), len);

  if (copy_to_user(buffer, out, nbytes_to_copy))
        return -EFAULT;
  *offset = *offset + nbytes_to_copy;
  return nbytes_to_copy;
}

/* Create a platform device given its name
 * 
 *  @param buffer Contains the name of the device, e.g. 
*/
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   char dev_name[256];
   struct platform_device *pdev;

   /** FIND FUNCS **/
   if(len >= 256)
   {
     printk("device_creator: input string should be less than 256, aborting\n");
     return -1;
   }
   if(copy_from_user(dev_name, buffer, len))
   {
     printk("device creator: copy_from_user failed, aborting\n");
     return -1;
   }
   dev_name[len] = '\0';
   if(dev_name[len-1] == '\n')
     dev_name[len-1] = '\0';

   pdev = get_platform_device_by_name(dev_name);
   if(!pdev)
   {
     printk("device creator: could not find device!\n");
     return -1;
   }

   if(platform_device_register(pdev))
   {
     printk("device creator: failed to create platform device!\n");
     return -1;
   }

   printk("device creator: device created successfully!\n");
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   //printk("device creator: dev file successfully closed\n");
   return 0;
}

module_init(dcreator_init);
module_exit(dcreator_exit);
