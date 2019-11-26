#ifndef _H_ENDIAN_MACRO_
#define _H_ENDIAN_MACRO_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif

#define CVAL(buf, pos) ((unsigned int)(((const uint8_t *)(buf))[pos]))
#define CVAL_NC(buf, pos) (((uint8_t *)(buf))[pos]) /* Non-const version of CVAL */
#define PVAL(buf, pos) (CVAL(buf,pos))
#define SCVAL(buf, pos, val) (CVAL_NC(buf,pos) = (val))

#define SVAL(buf, pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf, pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#define SSVALX(buf, pos, val) (CVAL_NC(buf,pos)=(uint8_t)((val)&0xFF),CVAL_NC(buf,pos+1)=(uint8_t)((val)>>8))
#define SIVALX(buf, pos, val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf, pos) ((int16_t)SVAL(buf,pos))
#define IVALS(buf, pos) ((int32_t)IVAL(buf,pos))
#define SSVAL(buf, pos, val) SSVALX((buf),(pos),((uint16_t)(val)))
#define SIVAL(buf, pos, val) SIVALX((buf),(pos),((uint32_t)(val)))
#define SSVALS(buf, pos, val) SSVALX((buf),(pos),((int16_t)(val)))
#define SIVALS(buf, pos, val) SIVALX((buf),(pos),((int32_t)(val)))

/* 64 bit macros */
#define BVAL(p, ofs) (IVAL(p,ofs) | (((uint64_t)IVAL(p,(ofs)+4)) << 32))
#define BVALS(p, ofs) ((int64_t)BVAL(p,ofs))
#define SBVAL(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,((uint64_t)(v))>>32))
#define SBVALS(p, ofs, v) (SBVAL(p,ofs,(uint64_t)v))

/* now the reverse routines */
#define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
#define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))
#define BREV(x) ((IREV(x)<<32) | (IREV((x)>>32)))

#define RSVAL(buf, pos) SREV(SVAL(buf,pos))
#define RSVALS(buf, pos) SREV(SVALS(buf,pos))
#define RIVAL(buf, pos) IREV(IVAL(buf,pos))
#define RIVALS(buf, pos) IREV(IVALS(buf,pos))
#define RBVAL(buf, pos) BREV(BVAL(buf,pos))
#define RBVALS(buf, pos) BREV(BVALS(buf,pos))
#define RSSVAL(buf, pos, val) SSVAL(buf,pos,SREV(val))
#define RSSVALS(buf, pos, val) SSVALS(buf,pos,SREV(val))
#define RSIVAL(buf, pos, val) SIVAL(buf,pos,IREV(val))
#define RSIVALS(buf, pos, val) SIVALS(buf,pos,IREV(val))
#define RSBVAL(buf, pos, val) SBVAL(buf,pos,BREV(val))
#define RSBVALS(buf, pos, val) SBVALS(buf,pos,BREV(val))

/* Alignment macros. */
#define ALIGN4(p,base) ((p) + ((4 - (PTR_DIFF((p), (base)) & 3)) & 3))
#define ALIGN2(p,base) ((p) + ((2 - (PTR_DIFF((p), (base)) & 1)) & 1))

#endif /* _H_ENDIAN_MACRO_ */
