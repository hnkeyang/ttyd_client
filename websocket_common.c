#include "websocket_common.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

#include <netinet/tcp.h>
 
//================================================== 加密方法 sha1哈希 ==================================================
 
typedef struct SHA1Context{  
    unsigned Message_Digest[5];        
    unsigned Length_Low;               
    unsigned Length_High;              
    unsigned char Message_Block[64];   
    int Message_Block_Index;           
    int Computed;                      
    int Corrupted;                     
} SHA1Context;  

#define SHA1CircularShift(bits,word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))  
 
void SHA1ProcessMessageBlock(SHA1Context *context)
{  
    const unsigned K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };  
    int         t;                  
    unsigned    temp;               
    unsigned    W[80];              
    unsigned    A, B, C, D, E;      
 
    for(t = 0; t < 16; t++) 
    {  
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);  
    }  
 
    for(t = 16; t < 80; t++)  
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);  
 
    A = context->Message_Digest[0];  
    B = context->Message_Digest[1];  
    C = context->Message_Digest[2];  
    D = context->Message_Digest[3];  
    E = context->Message_Digest[4];  
 
    for(t = 0; t < 20; t++) 
    {  
        temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 20; t < 40; t++) 
    {  
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 40; t < 60; t++) 
    {  
        temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 60; t < 80; t++) 
    {  
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = SHA1CircularShift(30,B);  
        B = A;  
        A = temp;  
    }  
    context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;  
    context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;  
    context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;  
    context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;  
    context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;  
    context->Message_Block_Index = 0;  
} 
 
void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;  
    context->Length_High            = 0;  
    context->Message_Block_Index    = 0;  
 
    context->Message_Digest[0]      = 0x67452301;  
    context->Message_Digest[1]      = 0xEFCDAB89;  
    context->Message_Digest[2]      = 0x98BADCFE;  
    context->Message_Digest[3]      = 0x10325476;  
    context->Message_Digest[4]      = 0xC3D2E1F0;  
 
    context->Computed   = 0;  
    context->Corrupted  = 0;  
}  
 
void SHA1PadMessage(SHA1Context *context)
{  
    if (context->Message_Block_Index > 55) 
    {  
        context->Message_Block[context->Message_Block_Index++] = 0x80;  
        while(context->Message_Block_Index < 64)  context->Message_Block[context->Message_Block_Index++] = 0;  
        SHA1ProcessMessageBlock(context);  
        while(context->Message_Block_Index < 56) context->Message_Block[context->Message_Block_Index++] = 0;  
    } 
    else 
    {  
        context->Message_Block[context->Message_Block_Index++] = 0x80;  
        while(context->Message_Block_Index < 56) context->Message_Block[context->Message_Block_Index++] = 0;  
    }  
    context->Message_Block[56] = (context->Length_High >> 24 ) & 0xFF;  
    context->Message_Block[57] = (context->Length_High >> 16 ) & 0xFF;  
    context->Message_Block[58] = (context->Length_High >> 8 ) & 0xFF;  
    context->Message_Block[59] = (context->Length_High) & 0xFF;  
    context->Message_Block[60] = (context->Length_Low >> 24 ) & 0xFF;  
    context->Message_Block[61] = (context->Length_Low >> 16 ) & 0xFF;  
    context->Message_Block[62] = (context->Length_Low >> 8 ) & 0xFF;  
    context->Message_Block[63] = (context->Length_Low) & 0xFF;  
 
    SHA1ProcessMessageBlock(context);  
} 
 
int SHA1Result(SHA1Context *context)
{
    if (context->Corrupted) 
    {  
        return 0;  
    }  
    if (!context->Computed) 
    {  
        SHA1PadMessage(context);  
        context->Computed = 1;  
    }  
    return 1;  
}  
 
 
void SHA1Input(SHA1Context *context,const char *message_array,unsigned length){  
    if (!length) 
        return;  
 
    if (context->Computed || context->Corrupted)
    {  
        context->Corrupted = 1;  
        return;  
    }  
 
    while(length-- && !context->Corrupted)
    {  
        context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);  
 
        context->Length_Low += 8;  
 
        context->Length_Low &= 0xFFFFFFFF;  
        if (context->Length_Low == 0)
        {  
            context->Length_High++;  
            context->Length_High &= 0xFFFFFFFF;  
            if (context->Length_High == 0) context->Corrupted = 1;  
        }  
 
        if (context->Message_Block_Index == 64)
        {  
            SHA1ProcessMessageBlock(context);  
        }  
        message_array++;  
    }  
}
 
/* 
int sha1_hash(const char *source, char *lrvar){// Main 
    SHA1Context sha; 
    char buf[128]; 
    SHA1Reset(&sha); 
    SHA1Input(&sha, source, strlen(source)); 
    if (!SHA1Result(&sha)){ 
        printf("SHA1 ERROR: Could not compute message digest"); 
        return -1; 
    } else { 
        memset(buf,0,sizeof(buf)); 
        sprintf(buf, "%08X%08X%08X%08X%08X", sha.Message_Digest[0],sha.Message_Digest[1], 
        sha.Message_Digest[2],sha.Message_Digest[3],sha.Message_Digest[4]); 
        //lr_save_string(buf, lrvar); 
        return strlen(buf); 
    } 
} 
*/  
char * sha1_hash(const char *source){   // Main  
    SHA1Context sha;  
    char *buf;//[128];  
 
    SHA1Reset(&sha);  
    SHA1Input(&sha, source, strlen(source));  
 
    if (!SHA1Result(&sha))
    {  
        printf("SHA1 ERROR: Could not compute message digest");  
        return NULL;  
    } 
    else 
    {  
        buf = (char *)malloc(128);  
        memset(buf, 0, 128);  
        sprintf(buf, "%08X%08X%08X%08X%08X", sha.Message_Digest[0],sha.Message_Digest[1],  
        sha.Message_Digest[2],sha.Message_Digest[3],sha.Message_Digest[4]);  
        //lr_save_string(buf, lrvar);  
 
        //return strlen(buf);  
        return buf;  
    }  
}  
 
int tolower(int c)   
{   
    if (c >= 'A' && c <= 'Z')   
    {   
        return c + 'a' - 'A';   
    }   
    else   
    {   
        return c;   
    }   
}
 
int htoi(const char s[], int start, int len)   
{   
    int i, j;   
    int n = 0;   
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X')) //判断是否有前导0x或者0X  
    {   
        i = 2;   
    }   
    else   
    {   
        i = 0;   
    }   
    i+=start;  
    j=0;  
    for (; (s[i] >= '0' && s[i] <= '9')   
       || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >='A' && s[i] <= 'F');++i)   
    {     
        if(j>=len)  
        {  
            break;  
        }  
        if (tolower(s[i]) > '9')   
        {   
            n = 16 * n + (10 + tolower(s[i]) - 'a');   
        }   
        else   
        {   
            n = 16 * n + (tolower(s[i]) - '0');   
        }   
        j++;  
    }   
    return n;   
}   
 
//================================================== 加密方法BASE64 ==================================================
 
//base64编/解码用的基础字符集
const char base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 
/*******************************************************************************
 * 名称: base64_encode
 * 功能: ascii编码为base64格式
 * 形参: bindata : ascii字符串输入
 *            base64 : base64字符串输出
 *          binlength : bindata的长度
 * 返回: base64字符串长度
 * 说明: 无
 ******************************************************************************/
int base64_encode( const unsigned char *bindata, char *base64, int binlength)
{
    int i, j;
    unsigned char current;
    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return j;
}
/*******************************************************************************
 * 名称: base64_decode
 * 功能: base64格式解码为ascii
 * 形参: base64 : base64字符串输入
 *            bindata : ascii字符串输出
 * 返回: 解码出来的ascii字符串长度
 * 说明: 无
 ******************************************************************************/
int base64_decode( const char *base64, unsigned char *bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) | \
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) | \
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) | \
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}


//==============================================================================================================
//================================================== websocket ==================================================
//==============================================================================================================
 
// 连接服务器
#define REPORT_LOGIN_CONNECT_TIMEOUT      1000                                                                       // 登录连接超时设置 1000ms
#define REPORT_LOGIN_RESPOND_TIMEOUT      (1000 + REPORT_LOGIN_CONNECT_TIMEOUT)    // 登录等待回应超时设置 1000ms
// 指令发收
#define REPORT_ANALYSIS_ERR_RESEND_DELAY    500     // 接收到回复内容但解析不通过, 延时 一段时间后重发指令      单位ms
// 生成握手key的长度
#define WEBSOCKET_SHAKE_KEY_LEN     16
/*
// websocket根据data[0]判别数据包类型
typedef enum{
    WCT_MINDATA = -20,      // 0x0：标识一个中间数据包
    WCT_TXTDATA = -19,      // 0x1：标识一个text类型数据包
    WCT_BINDATA = -18,      // 0x2：标识一个binary类型数据包
    WCT_DISCONN = -17,      // 0x8：标识一个断开连接类型数据包
    WCT_PING = -16,     // 0x8：标识一个断开连接类型数据包
    WCT_PONG = -15,     // 0xA：表示一个pong类型数据包
    WCT_ERR = -1,
    WCT_NULL = 0
}Websocket_CommunicationType;*/
 
/*******************************************************************************
 * 名称: webSocket_getRandomString
 * 功能: 生成随机字符串
 * 形参: *buf：随机字符串存储到
 *              len : 生成随机字符串长度
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
void webSocket_getRandomString(unsigned char *buf, unsigned int len)
{
    unsigned int i;
    unsigned char temp;
    srand((int)time(0));
    for(i = 0; i < len; i++)
    {
        temp = (unsigned char)(rand()%256);
        if(temp == 0)   // 随机数不要0, 0 会干扰对字符串长度的判断
            temp = 128;
        buf[i] = temp;
    }
}
/*******************************************************************************
 * 名称: webSocket_buildShakeKey
 * 功能: client端使用随机数构建握手用的key
 * 形参: *key：随机生成的握手key
 * 返回: key的长度
 * 说明: 无
 ******************************************************************************/
int webSocket_buildShakeKey(unsigned char *key)
{
    unsigned char tempKey[WEBSOCKET_SHAKE_KEY_LEN] = {0};
    webSocket_getRandomString(tempKey, WEBSOCKET_SHAKE_KEY_LEN);
    return base64_encode((const unsigned char *)tempKey, (char *)key, WEBSOCKET_SHAKE_KEY_LEN);
}
/*******************************************************************************
 * 名称: webSocket_buildRespondShakeKey
 * 功能: server端在接收client端的key后,构建回应用的key
 * 形参: *acceptKey：来自客户端的key字符串
 *         acceptKeyLen : 长度
 *          *respondKey :  在 acceptKey 之后加上 GUID, 再sha1哈希, 再转成base64得到 respondKey
 * 返回: respondKey的长度(肯定比acceptKey要长)
 * 说明: 无
 ******************************************************************************/
int webSocket_buildRespondShakeKey(unsigned char *acceptKey, unsigned int acceptKeyLen, unsigned char *respondKey)
{
    char *clientKey;  
    char *sha1DataTemp;  
    char *sha1Data;  
    int i, n;  
    const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";  
    unsigned int GUIDLEN;
 
    if(acceptKey == NULL)  
        return 0;  
    GUIDLEN = sizeof(GUID);
    clientKey = (char *)calloc(1, sizeof(char)*(acceptKeyLen + GUIDLEN + 10));  
    memset(clientKey, 0, (acceptKeyLen + GUIDLEN + 10));
    //
    memcpy(clientKey, acceptKey, acceptKeyLen); 
    memcpy(&clientKey[acceptKeyLen], GUID, GUIDLEN);
    clientKey[acceptKeyLen + GUIDLEN] = '\0';
    //
    sha1DataTemp = sha1_hash(clientKey);  
    n = strlen(sha1DataTemp);  
    sha1Data = (char *)calloc(1, n / 2 + 1);  
    memset(sha1Data, 0, n / 2 + 1);  
   //
    for(i = 0; i < n; i += 2)  
        sha1Data[ i / 2 ] = htoi(sha1DataTemp, i, 2);      
    n = base64_encode((const unsigned char *)sha1Data, (char *)respondKey, (n / 2));
    //
    free(sha1DataTemp);
    free(sha1Data);
    free(clientKey);
    return n;
}
/*******************************************************************************
 * 名称: webSocket_matchShakeKey
 * 功能: client端收到来自服务器回应的key后进行匹配,以验证握手成功
 * 形参: *myKey：client端请求握手时发给服务器的key
 *            myKeyLen : 长度
 *          *acceptKey : 服务器回应的key
 *           acceptKeyLen : 长度
 * 返回: 0 成功  -1 失败
 * 说明: 无
 ******************************************************************************/
int webSocket_matchShakeKey(unsigned char *myKey, unsigned int myKeyLen, unsigned char *acceptKey, unsigned int acceptKeyLen)
{
    int retLen;
    unsigned char tempKey[256] = {0};
    //
    retLen = webSocket_buildRespondShakeKey(myKey, myKeyLen, tempKey);
    //printf("webSocket_matchShakeKey :\r\n%d : %s\r\n%d : %s\r\n", acceptKeyLen, acceptKey, retLen, tempKey);
    //
    if(retLen != acceptKeyLen)
    {
        printf("webSocket_matchShakeKey : len err\r\n%s\r\n%s\r\n%s\r\n", myKey, tempKey, acceptKey);
        return -1;
    }
    else if(strcmp((const char *)tempKey, (const char *)acceptKey) != 0)
    {
        printf("webSocket_matchShakeKey : str err\r\n%s\r\n%s\r\n", tempKey, acceptKey);
        return -1;
    }
    return 0;
}
/*******************************************************************************
 * 名称: webSocket_buildHttpHead
 * 功能: 构建client端连接服务器时的http协议头, 注意websocket是GET形式的
 * 形参: *ip：要连接的服务器ip字符串
 *          port : 服务器端口
 *    *interfacePath : 要连接的端口地址
 *      *shakeKey : 握手key, 可以由任意的16位字符串打包成base64后得到
 *      *package : 存储最后打包好的内容
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
void webSocket_buildHttpHead(char *ip, int port, char *interfacePath, unsigned char *shakeKey, char *package)
{
    const char httpDemo[] = "GET %s HTTP/1.1\r\n"
                                                "Connection: Upgrade\r\n"
                                                "Host: %s:%d\r\n"
                                                "Sec-WebSocket-Key: %s\r\n"
                                                "Sec-WebSocket-Version: 13\r\n"
                                                "Sec-WebSocket-Protocol: tty\r\n"
                                                "Upgrade: websocket\r\n\r\n";
    sprintf(package, httpDemo, interfacePath, ip, port, shakeKey);
}
/*******************************************************************************
 * 名称: webSocket_buildHttpRespond
 * 功能: 构建server端回复client连接请求的http协议
 * 形参: *acceptKey：来自client的握手key
 *          acceptKeyLen : 长度
 *          *package : 存储
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
void webSocket_buildHttpRespond(unsigned char *acceptKey, unsigned int acceptKeyLen, char *package)
{
    const char httpDemo[] = "HTTP/1.1 101 Switching Protocols\r\n"
                                                "Upgrade: websocket\r\n"
                                                "Server: Microsoft-HTTPAPI/2.0\r\n"
                                                "Connection: Upgrade\r\n"
                                                "Sec-WebSocket-Accept: %s\r\n"
                                                "%s\r\n\r\n";  // 时间打包待续        // 格式如 "Date: Tue, 20 Jun 2017 08:50:41 CST\r\n"
    time_t now;
    struct tm *tm_now;
    char timeStr[256] = {0};
    unsigned char respondShakeKey[256] = {0};
    // 构建回应的握手key
    webSocket_buildRespondShakeKey(acceptKey, acceptKeyLen, respondShakeKey);   
    // 构建回应时间字符串
    time(&now);
    tm_now = localtime(&now);
    strftime(timeStr, sizeof(timeStr), "Date: %a, %d %b %Y %T %Z", tm_now);
    // 组成回复信息
    sprintf(package, httpDemo, respondShakeKey, timeStr);
}
/*******************************************************************************
 * 名称: webSocket_enPackage
 * 功能: websocket数据收发阶段的数据打包, 通常client发server的数据都要isMask(掩码)处理, 反之server到client却不用
 * 形参: *data：准备发出的数据
 *          dataLen : 长度
 *        *package : 打包后存储地址
 *        packageMaxLen : 存储地址可用长度
 *          isMask : 是否使用掩码     1要   0 不要
 *          type : 数据类型, 由打包后第一个字节决定, 这里默认是数据传输, 即0x81
 * 返回: 打包后的长度(会比原数据长2~16个字节不等)      <=0 打包失败 
 * 说明: 无
 ******************************************************************************/
int webSocket_enPackage(unsigned char *data, unsigned int dataLen, unsigned char *package, unsigned int packageMaxLen, bool isMask, Websocket_CommunicationType type)
{
    unsigned char maskKey[4] = {0};    // 掩码
    unsigned char temp1, temp2;
    int count;
    unsigned int i, len = 0;
 
    if(packageMaxLen < 2)
        return -1;
 
    if(type == WCT_MINDATA)
        *package++ = 0x00;
    else if(type == WCT_TXTDATA)
        *package++ = 0x81;
    else if(type == WCT_BINDATA)
        *package++ = 0x82;
    else if(type == WCT_DISCONN)
        *package++ = 0x88;
    else if(type == WCT_PING)
        *package++ = 0x89;
    else if(type == WCT_PONG)
        *package++ = 0x8A;
    else
        return -1;
    //
    if(isMask)
        *package = 0x80;
    len += 1;
    //
    if(dataLen < 126)
    {
        *package++ |= (dataLen&0x7F);
        len += 1;
    }
    else if(dataLen < 65536)
    {
        if(packageMaxLen < 4)
            return -1;
        *package++ |= 0x7E;
        *package++ = (char)((dataLen >> 8) & 0xFF);
        *package++ = (unsigned char)((dataLen >> 0) & 0xFF);
        len += 3;
    }
    else if(dataLen < 0xFFFFFFFF)
    {
        if(packageMaxLen < 10)
            return -1;
        *package++ |= 0x7F;
        *package++ = 0; //(char)((dataLen >> 56) & 0xFF);   // 数据长度变量是 unsigned int dataLen, 暂时没有那么多数据
        *package++ = 0; //(char)((dataLen >> 48) & 0xFF);
        *package++ = 0; //(char)((dataLen >> 40) & 0xFF);
        *package++ = 0; //(char)((dataLen >> 32) & 0xFF);
        *package++ = (char)((dataLen >> 24) & 0xFF);        // 到这里就够传4GB数据了
        *package++ = (char)((dataLen >> 16) & 0xFF);
        *package++ = (char)((dataLen >> 8) & 0xFF);
        *package++ = (char)((dataLen >> 0) & 0xFF);
        len += 9;
    }
    //
    if(isMask)    // 数据使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算, 逻辑如下
    {
        if(packageMaxLen < len + dataLen + 4)
            return -1;
        webSocket_getRandomString(maskKey, sizeof(maskKey));    // 随机生成掩码
        *package++ = maskKey[0];
        *package++ = maskKey[1];
        *package++ = maskKey[2];
        *package++ = maskKey[3];
        len += 4;
        for(i = 0, count = 0; i < dataLen; i++)
        {
            temp1 = maskKey[count];
            temp2 = data[i];
            *package++ = (char)(((~temp1)&temp2) | (temp1&(~temp2)));  // 异或运算后得到数据
            count += 1;
            if(count >= sizeof(maskKey))    // maskKey[4]循环使用
                count = 0;
        }
        len += i;
        *package = '\0';
    }
    else    // 数据没使用掩码, 直接复制数据段
    {
        if(packageMaxLen < len + dataLen)
            return -1;
        memcpy(package, data, dataLen);
        package[dataLen] = '\0';
        len += dataLen;
    }
    //
    return len;
}
/*******************************************************************************
 * 名称: webSocket_dePackage
 * 功能: websocket数据收发阶段的数据解包, 通常client发server的数据都要isMask(掩码)处理, 反之server到client却不用
 * 形参: *data：解包的数据
 *          dataLen : 长度
 *        *package : 解包后存储地址
 *        packageMaxLen : 存储地址可用长度
 *        *packageLen : 解包所得长度
 * 返回: 解包识别的数据类型 如 : txt数据, bin数据, ping, pong等
 * 说明: 无
 ******************************************************************************/
int webSocket_dePackage(unsigned char *data, unsigned int dataLen, unsigned char *package, unsigned int packageMaxLen, unsigned int *packageLen)
{
    unsigned char maskKey[4] = {0};    // 掩码
    unsigned char temp1, temp2;
    char Mask = 0, type;
    int count, ret;
    unsigned int i, len = 0, dataStart = 2;
    if(dataLen < 2)
        return -1;
 
    type = data[0]&0x0F;
 
    if((data[0]&0x80) == 0x80)
    {
        if(type == 0x01) 
            ret = WCT_TXTDATA;
        else if(type == 0x02) 
            ret = WCT_BINDATA;
        else if(type == 0x08) 
            ret = WCT_DISCONN;
        else if(type == 0x09) 
            ret = WCT_PING;
        else if(type == 0x0A) 
            ret = WCT_PONG;
        else 
            return WCT_ERR;
    }
    else if(type == 0x00) 
        ret = WCT_MINDATA;
    else
        return WCT_ERR;
    //
    if((data[1] & 0x80) == 0x80)
    {
        Mask = 1;
        count = 4;
    }
    else
    {
        Mask = 0;
        count = 0;
    }
    //
    len = data[1] & 0x7F;
    //
    if(len == 126)
    {
        if(dataLen < 4)
            return WCT_ERR;
        len = data[2];
        len = (len << 8) + data[3];
        if(dataLen < len + 4 + count)
            return WCT_ERR;
        if(Mask)
        {
            maskKey[0] = data[4];
            maskKey[1] = data[5];
            maskKey[2] = data[6];
            maskKey[3] = data[7];
            dataStart = 8;
        }
        else
            dataStart = 4;
    }
    else if(len == 127)
    {
        if(dataLen < 10)
            return WCT_ERR;
        if(data[2] != 0 || data[3] != 0 || data[4] != 0 || data[5] != 0)    // 使用8个字节存储长度时, 前4位必须为0, 装不下那么多数据...
            return WCT_ERR;
        len = data[6];
        len = (len << 8) + data[7];
        len = (len << 8) + data[8];
        len = (len << 8) + data[9];
        if(dataLen < len + 10 + count)
            return WCT_ERR;
        if(Mask)
        {
            maskKey[0] = data[10];
            maskKey[1] = data[11];
            maskKey[2] = data[12];
            maskKey[3] = data[13];
            dataStart = 14;
        }
        else
            dataStart = 10;
    }
    else
    {
        if(dataLen < len + 2 + count)
            return WCT_ERR;
        if(Mask)
        {
            maskKey[0] = data[2];
            maskKey[1] = data[3];
            maskKey[2] = data[4];
            maskKey[3] = data[5];
            dataStart = 6;
        }
        else
            dataStart = 2;
    }
    //
    if(dataLen < len + dataStart)
        return WCT_ERR;
    //
    if(packageMaxLen < len + 1)
        return WCT_ERR;
    //
    if(Mask)    // 解包数据使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算, 逻辑如下
    {
        //printf("depackage : len/%d\r\n", len);
        for(i = 0, count = 0; i < len; i++)
        {
            temp1 = maskKey[count];
            temp2 = data[i + dataStart];
            *package++ =  (char)(((~temp1)&temp2) | (temp1&(~temp2)));  // 异或运算后得到数据
            count += 1;
            if(count >= sizeof(maskKey))    // maskKey[4]循环使用
                count = 0;
            //printf("%.2X|%.2X|%.2X, ", temp1, temp2, *(package-1));
        }
        *package = '\0';
    }
    else    // 解包数据没使用掩码, 直接复制数据段
    {
        memcpy(package, &data[dataStart], len);
        package[len] = '\0';
    }
    *packageLen = len;
    //
    return ret;
}

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLS_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

/*   * Generates a NSS key log format compatible string containing the client
     * random and the master key, intended to be used to decrypt externally
     * captured network traffic using tools like Wireshark.
     *
     * Only supports the CLIENT_RANDOM method (SSL 3.0 - TLS 1.2).
     *
     * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
     */
    char* ssl_ssl_masterkey_to_str(SSL *ssl)
    {
        char *str = NULL;
        int rv;
        unsigned char *k, *r;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        unsigned char kbuf[48], rbuf[32];
        k = &kbuf[0];
        r = &rbuf[0];
        SSL_SESSION_get_master_key(SSL_get0_session(ssl), k, sizeof(kbuf));
        SSL_get_client_random(ssl, r, sizeof(rbuf));
#else /* OPENSSL_VERSION_NUMBER < 0x10100000L */
        k = ssl->session->master_key;
        r = ssl->s3->client_random;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
        rv = asprintf(&str,
                      "CLIENT_RANDOM "
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      " "
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "%02X%02X%02X%02X%02X%02X%02X%02X"
                      "\n",
                      r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
                      r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
                      r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
                      r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31],
                      k[ 0], k[ 1], k[ 2], k[ 3], k[ 4], k[ 5], k[ 6], k[ 7],
                      k[ 8], k[ 9], k[10], k[11], k[12], k[13], k[14], k[15],
                      k[16], k[17], k[18], k[19], k[20], k[21], k[22], k[23],
                      k[24], k[25], k[26], k[27], k[28], k[29], k[30], k[31],
                      k[32], k[33], k[34], k[35], k[36], k[37], k[38], k[39],
                      k[40], k[41], k[42], k[43], k[44], k[45], k[46], k[47]);

        return (rv < 0) ? NULL : str;
    }


int conn_write(struct tty_conn *conn, void*buffer, int len)
{
    int ret;
    if(conn->use_ssl){
        ret = SSL_write(conn->ssl, buffer, len);
    }else{
        ret = write(conn->fd, buffer, len);
    }
    return ret;
}

int conn_read(struct tty_conn *conn, void*buffer, int len)
{
    int ret;
    if(conn->use_ssl){
        ret = SSL_read(conn->ssl, buffer, len);
    }else{
        ret = read(conn->fd, buffer, len);
    }
    return ret;
}

/*******************************************************************************
 * 名称: webSocket_clientLinkToServer
 * 功能: 向websocket服务器发送http(携带握手key), 以和服务器构建连接, 非阻塞模式
 * 形参: *ip：服务器ip
 *          port : 服务器端口
 *       *interface_path : 接口地址
 * 返回: >0 返回连接句柄      <= 0 连接失败或超时, 所花费的时间 ms
 * 说明: 无
 ******************************************************************************/
int webSocket_clientLinkToServer(struct tty_conn *conn, char *hostname, int port, char *interface_path)
{
    struct hostent *host;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        printf("hostname: %s, gethostbyname error\n", hostname);
        goto err;
    }

    int ret, fd , timeOut;
    unsigned char loginBuf[512] = {0}, recBuf[512] = {0}, shakeKey[128] = {0}, *p;
 
    // zhd服务器端网络地址结构体   
    struct sockaddr_in report_addr;     
    memset(&report_addr,0,sizeof(report_addr));             // 数据初始化--清零     
    report_addr.sin_family = AF_INET;                           // 设置为IP通信     
    //report_addr.sin_addr.s_addr = inet_addr(ip);            // 服务器IP地址      
    report_addr.sin_addr.s_addr = *(long*)(host->h_addr);            // 服务器IP地址   
    report_addr.sin_port = htons(port);                             // 服务器端口号     
 
    //create unix socket  
    if((fd = socket(AF_INET,SOCK_STREAM, 0)) < 0) 
    {
        printf("webSocket : socket create failed\r\n"); 
        goto err;
    }

    //非阻塞
    //ret = fcntl(fd , F_GETFL , 0);
    //fcntl(fd , F_SETFL , ret | O_NONBLOCK);

    // 禁用TCP nagle 算法
    int enable = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&enable,sizeof(enable));
 
    //connect
    timeOut = 0;
    if(connect(fd , (struct sockaddr *)&report_addr,sizeof(struct sockaddr)) != 0)
    {
        printf("connect to %s:%d Failed\n", hostname, port);
        return -1;
    }
    conn->fd = fd;

    if(conn->use_ssl){

        SSL_CTX *ctx;
        // SSL *ssl;

        ctx = InitCTX();
        conn->ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_fd(conn->ssl, fd);    /* attach the socket descriptor */
        if ( SSL_connect(conn->ssl) == -1 )   /* perform the connection */
            ERR_print_errors_fp(stderr);

        /*
        FILE *f = fopen("ssl_session.txt", "w");
        SSL_SESSION *ss = SSL_get_session(ssl);
        SSL_SESSION_print_fp(f, ss);  
        fclose(f);

        // 导出 ssl master-key 用于wireshark解密 ssl 抓包
        FILE *f1 = fopen("ssl_log.txt", "w");
        char *log = ssl_ssl_masterkey_to_str(ssl);
        fwrite(log, sizeof(char), strlen(log), f1);
        fclose(f1);
        */
    }
    //发送http协议头
    memset(shakeKey, 0, sizeof(shakeKey));
    webSocket_buildShakeKey(shakeKey);  // 创建握手key
 
    memset(loginBuf, 0, sizeof(loginBuf));  // 创建协议包
    webSocket_buildHttpHead(hostname, port, interface_path, shakeKey, (char *)loginBuf);   
    // 发出协议包
    ret = conn_write(conn, loginBuf, strlen((const char*)loginBuf));
 
    memset(recBuf , 0 , sizeof(recBuf));
    ret = conn_read(conn, recBuf, sizeof(recBuf));
    if(ret < 0)
    {   // Connect error
        goto err;
    }
    /*
        recBuf: 
        HTTP/1.1 101 Switching Protocols
        Sec-WebSocket-Accept: oQQlglpW1atmfyElnyoocUXnqkY=
        Sec-WebSocket-Protocol: tty
        Connection: Upgrade
        Upgrade: WebSocket
    */
    if(strncmp((const char *)recBuf, (const char *)"HTTP", strlen((const char *)"HTTP")) != 0)    // 返回的是http回应信息
    {
        printf("response not http message\n");
        goto err;
    }

    if((p = (unsigned char *)strstr((const char *)recBuf, (const char *)"Sec-WebSocket-Accept: ")) == NULL)    // 检查握手信号
    {
        //Sec-WebSocket-Accept: oQQlglpW1atmfyElnyoocUXnqkY=
        printf("%s\n", recBuf);
        printf("no handshake packet\n");
        goto err;
    }

    p += strlen((const char *)"Sec-WebSocket-Accept: ");
    sscanf((const char *)p, "%s\r\n", p);
    // printf("mykey: %s\n", shakeKey);
    // printf("serverkey: %s\n", p);
    if(webSocket_matchShakeKey(shakeKey, strlen((const char *)shakeKey), p, strlen((const char *)p)) == 0)  // 握手成功, 发送登录数据包
    {
        return 0; // 连接成功, 返回 0
    } else {
        goto err;
    }

err:
    SSL_free(conn->ssl); 
    close(conn->fd); 
    return -1;
}

/*******************************************************************************
 * 名称: webSocket_send
 * 功能: websocket数据基本打包和发送
 * 形参: fd：连接句柄
 *          *data : 数据
 *          dataLen : 长度
 *          mod : 数据是否使用掩码, 客户端到服务器必须使用掩码模式
 *          type : 数据要要以什么识别头类型发送(txt, bin, ping, pong ...)
 * 返回: 调用send的返回
 * 说明: 无
 ******************************************************************************/
int webSocket_send(struct tty_conn *conn, unsigned char *data, unsigned int dataLen, bool mod, Websocket_CommunicationType type)
{
    unsigned char *webSocketPackage;
    unsigned int retLen, ret;
    //unsigned int i;
 
    //---------- websocket数据打包 ---------- 128->2000
    int packageMaxLen = dataLen + 128;
    webSocketPackage = (unsigned char *)calloc(1, sizeof(char)*packageMaxLen);  memset(webSocketPackage, 0, packageMaxLen);
    retLen = webSocket_enPackage(data, dataLen, webSocketPackage, packageMaxLen, mod, type);

    ret = conn_write(conn,webSocketPackage, retLen);
    free(webSocketPackage);
    return ret;
}
/*******************************************************************************
 * 名称: webSocket_recv
 * 功能: websocket数据接收和基本解包
 * 形参: fd：连接句柄
 *          *data : 数据接收地址
 *          dataMaxLen : 接收区可用最大长度
 * 返回: <= 0 没有收到有效数据        > 0 成功接收并解包数据
 * 说明: 无
 ******************************************************************************/
int webSocket_recv(struct tty_conn *conn, unsigned char *data, unsigned int dataMaxLen)
{
    unsigned char *recvBuf;
    int nread, ws_type = 0;
    unsigned int ws_len = 0;
 
    recvBuf = (unsigned char *)calloc(1, sizeof(char)*dataMaxLen);
    memset(recvBuf, 0, dataMaxLen);
    nread = conn_read(conn, recvBuf, dataMaxLen);
    // printf("nread: %d, errorno: %d\n", nread, errno);

    // 把从SSL读到的数据直接复制出去，不复制解析后的，有可能一个包里有多个websocket包，在外面再解析
    memcpy(data, recvBuf, nread);

    free(recvBuf);
    return nread;
}
