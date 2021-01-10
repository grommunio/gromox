#pragma once
#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif

#define CVAL(buf, pos) ((unsigned int)(((const uint8_t *)(buf))[pos]))
#define CVAL_NC(buf, pos) (((uint8_t *)(buf))[pos]) /* Non-const version of CVAL */
#define SCVAL(buf, pos, val) (CVAL_NC(buf,pos) = (val))

#define SVAL(buf, pos) (CVAL((buf), (pos)) | CVAL((buf), (pos) + 1) << 8)
#define IVAL(buf, pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf, pos, val) (CVAL_NC(buf,pos)=(uint8_t)((val)&0xFF),CVAL_NC(buf,pos+1)=(uint8_t)((val)>>8))
#define SIVALX(buf, pos, val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define IVALS(buf, pos) ((int32_t)IVAL(buf,pos))
#define SSVAL(buf, pos, val) SSVALX((buf),(pos),((uint16_t)(val)))
#define SIVAL(buf, pos, val) SIVALX((buf),(pos),((uint32_t)(val)))
#define SIVALS(buf, pos, val) SIVALX((buf),(pos),((int32_t)(val)))

/* now the reverse routines */
#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))
#define RSVAL(buf, pos) SREV(SVAL(buf,pos))
#define RIVAL(buf, pos) IREV(IVAL(buf,pos))
#define RIVALS(buf, pos) IREV(IVALS(buf,pos))
#define RSSVAL(buf, pos, val) SSVAL(buf,pos,SREV(val))
#define RSIVAL(buf, pos, val) SIVAL(buf,pos,IREV(val))
#define RSIVALS(buf, pos, val) SIVALS(buf,pos,IREV(val))
