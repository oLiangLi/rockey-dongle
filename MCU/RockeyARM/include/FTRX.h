#ifndef _FTRX_H
#define _FTRX_H

typedef unsigned int     DWORD;
typedef unsigned short   WORD;
typedef unsigned char    BYTE;

#define PIN_NONE        0x00 //匿名态
#define PIN_USER        0x01 //用户态
#define PIN_ADMIN       0x02 //开发商态

#define LED_OFF			0x00 //灯灭
#define LED_ON			0x01 //灯亮
#define LED_BLINK		0x02 //灯闪

#define MODE_ENCODE      0   //加密
#define MODE_DECODE      1   //解密

#define FILE_DATA                 1 //普通数据文件
#define FILE_PRIKEY_RSA           2 //RSA私钥文件
#define FILE_PRIKEY_ECCSM2        3 //ECC或SM2私钥文件
#define FILE_KEY                  4 //SM4或3DES密钥文件
#define FILE_EXE                  5 //可执行文件

//通用
#define ERR_SUCCESS           0x9000  //操作成功
#define ERR_INVALID_INS       0x6C00  //无效的INS
#define ERR_INVALID_P1        0x6C01  //无效的P1
#define ERR_INVALID_P2        0x6C02  //无效的P2
#define ERR_INVALID_LEN       0x6C03  //无效的LEN
#define ERR_INVALID_PARAM     0x6C04  //无效的参数(如:数据中的一些参数)
#define ERR_FAILED            0x6C05  //操作失败

//读写数据
#define ERR_READ_ERR          0x6B00  //读数据错误
#define ERR_WRITE_ERR         0x6B01  //写数据错误

//文件系统
#define ERR_FILE_EXIST        0x6A82  //文件已存在
#define ERR_FILE_NOTFOUND     0x6A83  //文件不存在
#define ERR_FILE_CFILE_ERR    0x6A86  //创建文件失败
#define ERR_FILE_READ_ERR     0x6A87  //读文件失败
#define ERR_FILE_WRITE_ERR    0x6A88  //写文件失败
#define ERR_FILE_DFILE_ERR    0x6A89  //删文件失败
#define ERR_FILE_CDIR_ERR     0x6A8A  //创建文件夹失败
#define ERR_FILE_DDIR_ERR     0x6A8B  //删除文件夹失败

//权限相关
#define ERR_NOT_INITED        0x6980  //尚未初始化
#define ERR_ALREADY_INITED    0x6981  //已初始化过了
#define ERR_ADMINPIN_NOTCHECK 0x6982  //管理员PIN没有校验
#define ERR_USERPIN_NOTCHECK  0x6983  //用户PIN没有校验
#define ERR_PIN_BLOCKED       0x6984  //PIN码已被锁定
#define ERR_RUN_LIMITED       0x6985  //运行已受限(如:私钥运算、种子码运算)

//锁的信息
typedef struct
{	
	unsigned short  m_Ver;               //COS版本,比如:0x0201,表示2.01版 
	unsigned short  m_Type;              //硬件类型: 0xFF表示标准锁, 0x00表示时钟锁, 0x02表示标准U盘锁   
	unsigned char   m_BirthDay[8];       //出厂日期
	unsigned long   m_Agent;             //代理商编号,比如:默认的0x00000000
	unsigned long   m_PID;               //产品ID
	unsigned long   m_UserID;            //用户ID
	unsigned char   m_HID[8];            //8字节的硬件ID
	unsigned long   m_IsMother;          //母锁标志: 0x01表示是母锁, 0x00表示不是母锁     
	
} DONGLE_INFO;

//数据文件授权结构
typedef struct
{
	unsigned short  m_Read_Priv;      //读权限: 0为最小匿名权限  1为最小用户权限  2为最小管理员权限
	unsigned short  m_WritePriv;      //写权限: 0为最小匿名权限  1为最小用户权限  2为最小管理员权限

} DATA_LIC;

//数据文件属性数据结构
typedef struct
{
	unsigned long   m_Size;      //数据文件长度
	DATA_LIC        m_Lic;       //授权

} DATA_FILE_ATTR;

//私钥文件授权结构
typedef struct
{
	long           m_Count;      //可调次数: 0xFFFFFFFF表示不限制, 递减到0表示已不可调用
	unsigned char  m_Priv;       //调用权限: 0为最小匿名权限  1为最小用户权限  2为最小管理员权限
	unsigned char  m_IsDecOnRAM; //是否是在内存中递减: 1为在内存中递减    0为在FLASH中递减   
	unsigned char  m_IsReset;    //用户态调用后是否自动回到匿名态: 1为调后回到匿名态 (管理员态不受此限制)
	unsigned char  m_Reserve;    //保留,用于4字节对齐

} PRIKEY_LIC;

//密钥文件授权结构
typedef struct
{
	unsigned long  m_Priv_Enc;   //加密调用权限: 0为最小匿名权限  1为最小用户权限  2为最小管理员权限

} KEY_LIC;

//SM2、ECC及RSA私钥文件属性数据结构
typedef struct
{
	unsigned short  m_Type;       //数据类型:ECC私钥 或 RSA私钥
	unsigned short  m_Size;       //数据长度:对rsa来说是1024位或2048位, 对ecc来说是192位或256位, 对SM2来说是256位
	PRIKEY_LIC      m_Lic;        //授权

} PRIKEY_FILE_ATTR;

//SM4或TDES密钥文件属性数据结构
typedef struct
{
	unsigned long  m_Size;       //密钥数据长度,正常是16
	KEY_LIC     m_Lic;           //授权

} KEY_FILE_ATTR;

//外部RSA公钥格式(兼容1024,2048)
typedef struct {
	unsigned int  bits;                   // length in bits of modulus
	unsigned int  modulus;                // modulus
	unsigned char exponent[256];          // public exponent
} RSA_PUBLIC_KEY;
	
//外部RSA私钥格式(兼容1024,2048)
typedef struct {
	unsigned int  bits;                   // length in bits of modulus
	unsigned int  modulus;                // modulus
	unsigned char publicExponent[256];    // public exponent
	unsigned char exponent[256];          // private exponent
} RSA_PRIVATE_KEY;

//外部ECC\SM2公钥格式
typedef struct {
	unsigned int bits;
	unsigned int XCoordinate[8];
	unsigned int YCoordinate[8];
}ECCSM2_PUBLIC_KEY;

//外部ECCSM2私钥格式
typedef struct {
	unsigned int bits;
	unsigned int PrivateKey[8];
} ECCSM2_PRIVATE_KEY;

//ECCSM2公私钥对格式
typedef struct {
    ECCSM2_PRIVATE_KEY Prikey;
	ECCSM2_PUBLIC_KEY  Pubkey;
} ECCSM2_KEY_PAIR;

//=======================================================
//创建文件
extern WORD  create_file(WORD type, WORD  fileid, BYTE* pattr, int len_attr);
//读取数据文件,当fileid=0xFFFF时表示读取8K数据区
extern WORD  read_file(WORD fileid, WORD offset, WORD len, BYTE* pbuf);
//写文件
extern WORD  write_file(WORD type, WORD fileid, WORD offset, WORD len, BYTE* pbuf);
//删除文件
extern WORD  delete_file(WORD type, WORD fileid);
//取KEY的信息
extern WORD  get_keyinfo(DONGLE_INFO * pKI);
//取当前PIN码的权限状态
extern WORD  get_pinstate(DWORD * pState);
//LED灯的控制
extern WORD  led_control(BYTE flag);
//取随机数
extern WORD  get_random(BYTE* pbuf, BYTE len);
//取锁的上电时间,单位是ms,精度是100ms
extern WORD  get_tickcount(DWORD * pCount);
//取实时钟的时间
extern WORD  get_realtime(DWORD * pTime);
//取时钟锁的到期时间
extern WORD  get_expiretime(DWORD * pTime);
//读共享内存(32字节长)
extern WORD  get_sharememory(BYTE * pbuf);
//写共享内存(32字节长)
extern WORD  set_sharememory(BYTE * pbuf);
//rsa产生公私钥对
extern WORD  rsa_genkey(WORD fileid, RSA_PRIVATE_KEY * pRPK);
//rsa私钥加解密运算
extern WORD  rsa_pri(WORD fileid, BYTE * pIn, WORD len, BYTE * pOut, WORD * plen_Out, WORD mode);
//rsa公钥加解密运算
extern WORD  rsa_pub(BYTE * pIn, WORD len, RSA_PUBLIC_KEY * pPub, BYTE * pOut, WORD * plen_Out, WORD mode);
//ecc产生公私钥对
extern WORD  ecc_genkey(WORD fileid, ECCSM2_KEY_PAIR * pEKP);
//ecc私钥加解密运算
extern WORD  ecc_sign(WORD fileid, BYTE * pIn, WORD len, BYTE * pOut, WORD * plen_Out);
//ecc公钥加解密运算
extern WORD  ecc_verify(ECCSM2_PUBLIC_KEY * pEPK, BYTE * pHash, WORD len_Hash, BYTE * pSign);
//sm2产生公私钥对
extern WORD  sm2_genkey(WORD fileid, ECCSM2_KEY_PAIR * pEKP);
//sm2私钥加解密运算
extern WORD  sm2_sign(WORD fileid, BYTE * pIn, WORD len, BYTE * pOut, WORD * plen_Out);
//sm2公钥加解密运算
extern WORD  sm2_verify(ECCSM2_PUBLIC_KEY * pEPK, BYTE * pHash, WORD len_Hash, BYTE * pSign);
//TDES加解密运算
extern WORD  tdes(BYTE * pdata ,int len, int mode, WORD fileid);
//SM4加解密运算
extern WORD  sm4(BYTE * pdata ,int len, int mode, WORD fileid);
//sha1的hash运算
extern WORD  sha1(BYTE * pdata ,int len, BYTE * phash);
//sm3的hash运算
extern WORD  sm3(BYTE * pdata ,int len, BYTE * phash);
//seed种子码运算
extern WORD  seed(BYTE * pseed ,int len, BYTE * presult);
//TDES运算，秘钥传byte数组
extern WORD  tdes_raw(BYTE* pdata ,int len, int mode, BYTE* pkey);
//RSA运算，私钥传值
extern WORD  rsa_pri_raw(RSA_PRIVATE_KEY * pPri, BYTE* pIn, WORD len, BYTE* pOut, WORD* plen_Out, WORD mode);

extern WORD  sm4_raw(BYTE* pdata ,int len, int mode, BYTE* pkey);

extern WORD  ecc_sign_raw(ECCSM2_PRIVATE_KEY * pPri, BYTE* pIn, WORD len, BYTE* pOut, WORD* plen_Out);
extern WORD  sm2_sign_raw(ECCSM2_PRIVATE_KEY * pPri, BYTE* pIn, WORD len, BYTE* pOut, WORD* plen_Out);
//设置到期时间
extern WORD  set_expiretime(DWORD Time);

//sm2加密运算
extern WORD  sm2_encrypt(ECCSM2_PUBLIC_KEY* pEPK, BYTE* pIn, WORD len, BYTE* pOut);
//sm2解密运算(基于密钥文件)
extern WORD  sm2_decrypt(WORD fileid, BYTE* pIn, WORD len, BYTE* pOut, WORD* plen_Out);
//sm2解密运算(基于外部密钥)
extern WORD  sm2_decrypt_key(ECCSM2_PRIVATE_KEY * pPri, BYTE* pIn, WORD len, BYTE* pOut, WORD* plen_Out);

#endif
