
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/*
 * CRC循环冗余校验原理:
 * 先在要发送的帧后面附加一个数(这个数就是用来做校验的校验码)，生成一个新帧发送给接收端。
 * 当然这个附加的数不是随意的，它要使所生成的新帧能被发送端和接收端共同选定的某个特定的
 * 数整除(这里采用的除法是"模2除法")。帧到达接收端后，再把接收到的帧除以这个选定的除数。
 * 因为发送端发送数据帧之前已经附加了一个数，做了"去余"处理，所以接收端新帧除以这个数后
 * 肯定是可以整除的，没有余数，如果有余数则表明该帧在传输过程中出现了差错。
 *
 * 模2除法:
 * “模2除法”与“算术除法”类似，但它既不向上位借位，也不比较除数和被除数的相同位数值的大小，
 * 只要以相同位数进行相除即可。模2加法运算为：1+1=0，0+1=1，0+0=0，无进位，也无借位；
 * 模2减法运算为：1-1=0，0-1=1，1-0=1，0-0=0，也无进位，无借位。相当于二进制中的逻辑异或运算。
 * 也就是比较后，两者对应位相同则结果为“0”，不同则结果为“1”。如100101除以1110，结果得到商为11，余数为1
 *
 * CRC校验码计算:
 * 
 * 现假设选择的CRC生成多项式为G（X） = X4 + X3 + 1，要求出二进制序列10110011的CRC校验码。下面是具体的计算过程：
 *
 *（1）首先把生成多项式转换成二进制数，由G（X） = X4 + X3 + 1可以知道（，它一共是5位（总位数等于最高位的幂次加1，
 * 即4+1=5），然后根据多项式各项的含义（多项式只列出二进制值为1的位，也就是这个二进制的第4位、第3位、第0位的二进制均为1，
 * 其它位均为0）很快就可得到它的二进制比特串为11001。
 *（2）因为生成多项式的位数为5，根据前面的介绍，得知CRC校验码的位数为4（校验码的位数比生成多项式的位数少1）。
 * 因为原数据帧10110011，在它后面再加4个0，得到101100110000，然后把这个数以“模2除法”方式除以生成多项式，
 * 得到的余数（即CRC码）为0100.
 *（3）把上步计算得到的CRC校验0100替换原始帧101100110000后面的四个“0”，得到新帧101100110100。再把这个新帧发送到接收端。
 *（4）当以上新帧到达接收端后，接收端会把这个新帧再用上面选定的除数11001以“模2除法”方式去除，验证余数是否为0，
 * 如果为0，则证明该帧数据在传输过程中没有出现差错，否则出现了差错。
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The code and lookup tables are based on the algorithm
 * described at http://www.w3.org/TR/PNG/
 *
 * The 256 element lookup table takes 1024 bytes, and it may be completely
 * cached after processing about 30-60 bytes of data.  So for short data
 * we use the 16 element lookup table that takes only 64 bytes and align it
 * to CPU cache line size.  Of course, the small table adds code inside
 * CRC32 loop, but the cache misses overhead is bigger than overhead of
 * the additional code.  For example, ngx_crc32_short() of 16 bytes of data
 * takes half as much CPU clocks than ngx_crc32_long().
 */


static uint32_t  ngx_crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};


uint32_t  ngx_crc32_table256[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


uint32_t *ngx_crc32_table_short = ngx_crc32_table16;

/*初始化循环冗余校验表，后续校验可以直接通过查表法*/
ngx_int_t
ngx_crc32_table_init(void)
{
    void  *p;

    /*这个判断为真，表明ngx_crc32_table_short的地址对于cpu缓存行大小(ngx_cacheline_size)来说是对齐的。*/
    if (((uintptr_t) ngx_crc32_table_short
          & ~((uintptr_t) ngx_cacheline_size - 1))
        == (uintptr_t) ngx_crc32_table_short)
    {
        return NGX_OK;
    }

    p = ngx_alloc(16 * sizeof(uint32_t) + ngx_cacheline_size, ngx_cycle->log);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p = ngx_align_ptr(p, ngx_cacheline_size);  //让p对ngx_cacheline_size大小进行地址对齐

    ngx_memcpy(p, ngx_crc32_table16, 16 * sizeof(uint32_t)); //拷贝

    ngx_crc32_table_short = p;

    return NGX_OK;
}
